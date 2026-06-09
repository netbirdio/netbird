# NetBird Wails UI — Working Notes

This is the Wails v3 desktop UI for NetBird. Go services live in `services/`; the React/TS frontend lives in `frontend/`; bindings between them are generated under `frontend/bindings/`.

> **Keep these notes current.** When working in this directory with Claude, update this file (and `frontend/CLAUDE.md` for frontend-only changes) whenever you add a service, change an event name, shift a convention, rename a key directory, or land any other change that future-you would want to know about before reading the code. The goal is that a cold-start agent can orient itself from these notes without re-deriving the codebase.

## Layout

### Go (top-level package `main`)
- `main.go` — app entry. Builds the shared gRPC `Conn`, constructs services, registers them with Wails, creates the main webview window, then starts (in order) the Linux SNI watcher → tray → `peers.Watch` → `app.Run`. CLI flags: `--daemon-addr`, `--log-file` (repeatable; first user-provided value drops the seeded `console` default), `--log-level` (`trace|debug|info|warn|error`, default `info`).
- `tray.go` — `Tray` struct + menu. Subscribes to `EventStatus`, `EventSystem`, `EventUpdateAvailable`, `EventUpdateProgress`. Owns per-status icon/dot, Profiles submenu, Connect/Disconnect swap, About → Update, session-expired toast.
- **Tray menu updates go through `relayoutMenu` (whole-tree rebuild), never in-place submenu mutation.** Any dynamic menu change — Profiles submenu (`tray_profiles.go loadProfiles` → caches rows under `profilesMu`, then `fillProfileSubmenu`), Exit Node submenu (`tray_exitnodes.go refreshExitNodes` → `fillExitNodeSubmenu`), daemon-version row (`tray_status.go`), and the About → Update row (`tray_update.go applyState` → `onMenuChange` callback) — rebuilds the entire menu via `Tray.relayoutMenu` (`buildMenu()` + repaint cached state + single `t.tray.SetMenu`). Serialised by `menuMu`. **Why:** on KDE/Plasma the StatusNotifierItem host caches a submenu's layout the first time it's opened (`GetLayout` for that submenu id) and never re-fetches it on a `LayoutUpdated(parent=0)` signal — so the old `submenu.Clear()`+`Add()` left both the visible rows AND the click→id mapping frozen on the first snapshot. Because `Clear()`+`Add()` allocates fresh monotonic item ids each time (Wails `menuitem.go`), clicks then sent ids the rebuilt `itemMap` no longer knew, and silently no-op'd ("Manage Profiles" stopped responding after the first switch). `buildMenu()` allocates a brand-new submenu container id each relayout, which Plasma treats as unseen and re-queries on next open — fixing both the stale paint and the dead clicks. Confirmed via `dbus-monitor`: a re-opened submenu issued no `GetLayout` until its container id changed. The whole-tree `SetMenu` also subsumes the older darwin detached-NSMenu workaround. `fill*Submenu` helpers are pure UI (read caches, no daemon fetch, no `SetMenu`) so `relayoutMenu` never recurses back into the fetchers.
- `tray_linux.go` — `init()` sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` (blank-white window on VMs / minimal WMs) and `WEBKIT_DISABLE_COMPOSITING_MODE=1` (Intel/Mesa SIGSEGV in `g_application_run` via unimplemented DRM-format-modifier paths — DMABUF-disable alone doesn't cover the GL compositor). Both are skipped if the user already set the var. Also `WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1` when unprivileged userns are blocked.
- `tray_watcher_linux.go`, `xembed_host_linux.go`, `xembed_tray_linux.{c,h}` — in-process SNI watcher + XEmbed bridge for minimal WMs. See `LINUX-TRAY.md`.
- `signal_unix.go` / `signal_windows.go` — `listenForShowSignal`. Unix uses SIGUSR1; Windows uses a named event `Global\NetBirdQuickActionsTriggerEvent`. Mirrors the legacy Fyne UI's external-trigger contract so the installer / CLI keep working.
- `grpc.go` — lazy, mutex-protected gRPC `Conn` shared by every service. `DaemonAddr()`: `unix:///var/run/netbird.sock` on Linux/macOS, `tcp://127.0.0.1:41731` on Windows.
- `icons.go` — `//go:embed` tray/window PNGs. macOS uses template variants (`*-macos.png`); Linux uses a monochrome black/white pair (`*-mono.png` black for light panels, `*-mono-dark.png` white for dark panels); Windows reuses the colored light PNG (multi-frame `.ico` never redrew on Wails3's `NIM_MODIFY`). The `*-mono*` set is generated from the macOS template silhouettes (states differ by shape, not color); `tray_icon.go iconForState` branches on `runtime.GOOS` (`linux` → mono, else colored).
- **Linux mono icon theme selection** — Wails v3's Linux SNI backend ignores `SetDarkModeIcon` (its `setDarkModeIcon` just calls `setIcon`, last-write-wins — see `pkg/application/systemtray_linux.go`), and the SNI spec carries no panel light/dark hint. So `tray_theme_linux.go` detects the desktop colour scheme itself and `iconForState` picks black-vs-white, with `applyIcon` pushing a single `SetIcon` on Linux (no `SetDarkModeIcon`). Detection order: freedesktop **Settings portal** (`org.freedesktop.portal.Settings.Read` of `org.freedesktop.appearance`/`color-scheme`: 0=no-pref, 1=dark, 2=light) → on 0/unavailable, fall back to the **`GTK_THEME`** env var (`:dark` suffix ⇒ dark) → else default dark (suits the common dark panel). A private session-bus `SettingChanged` subscription repaints live on theme flips. `Tray.panelDark func() bool` is seeded by `startTrayTheme()` (Linux only; `tray_theme_other.go` is a no-op stub) before the first `applyIcon`; `panelIsDark()` returns true when `panelDark` is nil.

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
| `Update` | `update.go` | `GetState` / `Trigger` (enforced installer) / `GetInstallerResult` / `Quit`. The install-progress UI lives in its own auxiliary window (`/#/dialog/install-progress`), opened by `WindowManager.OpenInstallProgress` — the daemon goes unreachable mid-install so it can't be inside the main window. |
| `WindowManager` | `windowmanager.go` | `OpenSettings(tab)` / `OpenBrowserLogin(uri)` / `CloseBrowserLogin` / `OpenSessionExpiration(seconds)` / `CloseSessionExpiration` / `OpenInstallProgress(version)` / `CloseInstallProgress` / `OpenWelcome` / `CloseWelcome` / `OpenError(title, message)` / `CloseError` / `OpenMain`. `OpenSettings("")` opens the General tab; pass a tab id (e.g. `"profiles"`) to deep-link, encoded as `?tab=…` in the start URL. `OpenInstallProgress` is `AlwaysOnTop` and hides every other visible window for the duration of the install (restored on close). `OpenMain` is the handoff path from the welcome window to the main UI (avoids depending on the tray). Auxiliary windows are created on first open and **destroyed** on close (Wails-recommended singleton pattern; prevents the macOS dock-reopen from resurrecting hidden windows). |
| `I18n` | `i18n.go` | Thin facade over `i18n.Bundle`. `Languages()` returns the shipped locales (`_index.json`); `Bundle(code)` returns the full key→text map for one language so the React layer can drive its own translation library. |
| `Preferences` | `preferences.go` | Thin facade over `preferences.Store`. `Get()` returns `{language, viewMode, onboardingCompleted}`; `SetLanguage(code)` validates against `i18n.Bundle.HasLanguage` and persists; `SetViewMode(mode)` validates against the known set (`default`/`advanced`) and persists; `SetOnboardingCompleted(bool)` persists the welcome-window dismissal. All broadcast `netbird:preferences:changed`. `main.go` reads `viewMode` from the store to size the main window at startup. |
| `Autostart` | `autostart.go` | Thin facade over Wails' `app.Autostart` (`*application.AutostartManager`). `Supported()` / `IsEnabled()` / `SetEnabled(bool)` — launch-the-UI-at-login toggle. The OS login-item registration (launchd/SMAppService on macOS, `HKCU\…\Run` on Windows, XDG `.desktop` on Linux) is the **single source of truth** — nothing is mirrored to the preferences file. `Enable` registers the running executable with no extra args (the app comes up hidden into the tray). Affects the **graphical UI only**, not the daemon/background service. `Supported()` is false on server/mobile builds (`ErrAutostartNotSupported`); the React toggle in `SettingsGeneral.tsx` hides itself when false. |

`DaemonConn` is defined in `services/conn.go`; `ptrStr` (string-to-*string helper for proto pointer fields) lives there too.

## Daemon proto
- Proto source: `../proto/daemon.proto`. Generated Go in `../proto/*.pb.go`.
- Regen: `cd ../proto && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative daemon.proto`
- Pinned versions (see `daemon.pb.go` header): `protoc v7.34.1`, `protoc-gen-go v1.36.6`. CI's `proto-version-check` workflow fails on mismatch.
- After proto regen, also regen Wails bindings so the TS layer picks up new fields.

## Events bus

`main.go` registers five typed events for the frontend: `netbird:status` (`Status`), `netbird:event` (`SystemEvent`), `netbird:profile:changed` (`ProfileRef`), `netbird:update:available` (`UpdateAvailable`), `netbird:update:progress` (`UpdateProgress`). `netbird:profile:changed` fires from `ProfileSwitcher.SwitchActive` after a successful daemon-side switch — both the React `ProfileContext` and the tray subscribe so a flip driven from one surface paints in the others (the daemon itself does not emit a profile event). Plus three plain-string events:

- `EventTriggerLogin = "trigger-login"` — tray asking the frontend's `startLogin()` to begin an SSO flow. The tray does **not** show the main window when emitting — the hidden webview is alive and subscribed, so `startLogin` runs and the only visible surface is the BrowserLogin popup it opens.
- `EventBrowserLoginCancel = "browser-login:cancel"` — the `BrowserLogin` window's Cancel button or red-X close. `startLogin()` listens and tears down the daemon's pending `WaitSSOLogin`.
- `preferences.EventPreferencesChanged = "netbird:preferences:changed"` — emitted after every successful `SetLanguage` (payload `{language}`). Both the tray menu rebuild and the React `i18next.changeLanguage` subscribe so a flip from any window paints everywhere.
- `EventSettingsOpen = "netbird:settings:open"` (payload: tab string, e.g. `"general"` / `"profiles"`) — emitted by `WindowManager.OpenSettings(tab)` to set the active tab before Go calls `Show`/`Focus`. The matching reset-to-General on close lives in the React side via `document.visibilitychange` (Wails events from the Go close hook race `Hide` and flash the previous tab for one frame).

Daemon connection status strings (`services/peers.go`) mirror `internal.Status*` in `client/internal/state.go`: `Connected`, `Connecting`, `Idle`, `NeedsLogin`, `LoginFailed`, `SessionExpired`, plus the synthetic `DaemonUnavailable` emitted by `Peers` when the socket is unreachable.

## Profile switching

`services/profileswitcher.go` is the single source of truth for the reconnect policy. Both the tray (`tray.go switchProfile`) and the frontend (via `modules/profiles/ProfileContext.tsx`'s `switchProfile`, which `modules/profiles/ProfilesTab.tsx` and the header `ProfileDropdown` go through) call `ProfileSwitcher.SwitchActive`; identical inputs give identical state transitions.

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

- **Settings** (`/#/settings`) — opened from the header gear icon (`pages/main/Header.tsx → WindowManager.OpenSettings("")`), the tray's Settings menu entry (`tray.go openSettings`), and the profile dropdown's "Manage Profiles" entry (`WindowManager.OpenSettings("profiles")`, which sets `?tab=profiles` in the start URL — `Settings.tsx` reads it via `useSearchParams`). The window hosts every settings tab — including **Profiles** (`ProfilesTab.tsx`, `UserCircle` icon, sits between Security and SSH), which lists profiles in a table with Deregister/Delete in a per-row kebab and an Add Profile button. Both call sites go through `WindowManager` so the user sees the same dedicated frameless window from either trigger — the tray used to repurpose the main window via `SetURL("/#/settings")`, which replaced the main UI in place. Frameless-look (opaque macOS backdrop, hidden inset title bar), fixed 900×640, no resize, no minimise/maximise. **Unlike the other auxiliary windows**, Settings is created eagerly (hidden) inside `NewWindowManager` and hides on close instead of being destroyed — first open is instant. The window stays at a single URL (`/#/settings`) forever; `OpenSettings(tab)` does **not** call `SetURL`. Instead it emits `netbird:settings:open` with the target tab (empty → `"general"`), then calls `Show`/`Focus`. `SettingsPage` keeps the active tab in React local state and listens for the event to switch. **Reset-on-close lives in the React side**, not the Go close hook: `SettingsPage` listens for `document.visibilitychange` and resets the tab to General when the page goes hidden. Doing it via `Event.Emit` from the close hook didn't work — the dispatch goroutine races `Hide`, the JS listener often runs only after the *next* `Show`, and the user sees a one-frame flash of the previous tab. The Page Visibility API fires before WebKit throttles the page, so the state update lands while we're still in foreground JS. (The earlier `SetURL` path re-loaded the WKWebView entirely, re-mounting the `AppLayout` provider stack and visibly flashing the `SettingsSkeleton` while `SettingsContext` re-fetched config.)
- **BrowserLogin** (`/#/dialog/browser-login?uri=…`) — opened by the connection toggle's SSO flow (`pages/main/ConnectionStatusSwitch.tsx`). 460×440, fixed size. The close button (red X) fires `EventBrowserLoginCancel` so the JS-side `startLogin()` can tear down the daemon's pending `WaitSSOLogin`. `WindowManager.CloseBrowserLogin` closes it programmatically when the flow completes.
- **SessionExpiration** (`/#/dialog/session-expiration?seconds=<n>`) — opened by `WindowManager.OpenSessionExpiration(seconds)`. 460×380, fixed size, `AlwaysOnTop: true`. The React-side buttons close the window via `WindowManager.CloseSessionExpiration` and (for Sign-in / Stay-connected) emit `EventTriggerLogin` so the main window's `startLogin()` orchestrator handles the SSO flow. Triggered by the tray today: `tray_session.go openSessionExpiration` fires it at T-FinalWarningLead when the earlier T-10 notification wasn't dismissed, and `openSessionExtendFlow` opens it on tray-row click seeded with the live remaining time. **Multi-monitor aware** — targets the display the OS cursor is currently on via `WindowManager.getScreenBasedOnCursorPosition`, which queries the native cursor location per-OS through `getCursorPosition` (`services/cursor_{darwin,windows,linux,other}.go`): `NSEvent.mouseLocation` flipped against the primary's frame height on macOS, `w32.GetCursorPos` + ScreenManager `PhysicalToDipPoint` on Windows, X11 `XQueryPointer` on Linux. The X11 query covers Wayland sessions too via XWayland, which ships by default on every supported Linux target. **Verified distro coverage**: Windows, macOS, Ubuntu 22.04 + 24.04 (GNOME-Wayland default + XWayland), Fedora 40 (GNOME-Wayland + XWayland), Debian 12 (GNOME default + XWayland), Arch Linux (any DE/compositor + XWayland), Linux Mint (Cinnamon-Xorg → Xorg direct), GNOME (Xorg + Wayland), Fluxbox (Xorg, exercised by the xembed-tray test path). Falls back gracefully (no panic, no error) to the main window's screen, then the OS default, when the cursor can't be resolved (headless / no DISPLAY / pure-Wayland-without-XWayland). Both first-create and re-show go through a single helper, `WindowManager.centerOnCursorScreen`: synchronous SetPosition first (covers full desktops and re-show with a still-alive GTK surface), then on minimal WMs (`recenterOnShow` — the Fluxbox/XEmbed-tray path) the same ~1s realize-detection retry loop `centerWhenReady` uses, because Wails' Linux SetPosition silently no-ops against a nil GdkSurface and Fluxbox would otherwise leave the window on the primary monitor.
- **InstallProgress** (`/#/dialog/install-progress?version=<v>`) — opened by `WindowManager.OpenInstallProgress(version)` from `ClientVersionContext` (force-install branch on `installing` flip, user-driven enforced branch from `triggerUpdate`). 360-wide auto-sized via `useAutoSizeWindow`, `AlwaysOnTop`. Owns its own polling loop against `Update.GetInstallerResult` with the 5-second daemon-down-grace (sustained gRPC failure = success → call `Update.Quit()`). Hides every other visible window on open (restored on close).
- **Welcome** (`/#/dialog/welcome`) — first-launch onboarding window opened by `WindowManager.OpenWelcome()` from `main.go`'s `ApplicationStarted` hook, gated by `prefStore.Get().OnboardingCompleted` so it only fires on a fresh install. Auto-sized via `useAutoSizeWindow`, centered (`InitialPosition: WindowCentered`), inherits `AlwaysOnTop` from `DialogWindowOptions`. Two-step state machine: **(1)** tray-screenshot pitch with the per-OS tray icon; **(2)** Cloud-vs-self-hosted segmented control with optional URL input — only rendered when `shouldShowManagementStep` returns true (default profile + no recorded email + management URL is empty/cloud-default). The Continue button on either terminal step flips `Preferences.SetOnboardingCompleted(true)`, calls `WindowManager.OpenMain()`, then `WindowManager.CloseWelcome()`.

- **Error** (`/#/dialog/error?message=<m>`) — the app's single error surface, opened by `WindowManager.OpenError(title, message)`. **This replaced the native OS MessageBox outright**: the frontend `errorDialog({Title, Message})` wrapper in `lib/dialogs.ts` now drives this window (same name/signature as before, so call sites were untouched), and the native `Dialogs.Error`/`Warning`/`Info`/`Question` wrappers plus the Windows `Detached` workaround were deleted (nothing called warning/info/question). Frameless NetBird chrome, `AlwaysOnTop` (inherited from `DialogWindowOptions`), auto-sized to the variable-length message via `useAutoSizeWindow`. **`title` is the window's chrome title** — set Go-side as `"NetBird - <title>"` (empty falls back to the localised "Error"), *not* shown in the body — so it's excluded from `retitleAll` (a language flip must not clobber the live error title). **`message` is the body text**, carried as a query param (`errorDialogURL` query-escapes it so newlines/`&` in formatted daemon errors survive into `useSearchParams`). The left-aligned body is just the danger `SquareIcon` + message + a bottom-right Close button. A second error while one is open updates the live window (`SetTitle` + `SetURL`) instead of stacking another. Singleton, destroyed on close. The Close button (and the Escape key — keyboard cancellation) calls `WindowManager.CloseError()`. Note the behaviour change vs the old native box: `errorDialog()` resolves as soon as the window opens (it no longer blocks until dismissed). **macOS caveat:** the window uses `MacTitleBarHiddenInset`, so the chrome title isn't visibly rendered there — on macOS the error name would not be shown anywhere since it's no longer in the body.

The four lazy auxiliary windows (BrowserLogin, SessionExpiration, InstallProgress, Error) are **destroyed** on close (mutex-guarded singleton; `closing` hook nils the field). Destroying rather than hiding is deliberate — Wails' macOS dock-reopen handler resurrects hidden windows, which we don't want for transient surfaces. Settings is the exception: it's created hidden up-front and uses a `RegisterHook` close interceptor (`e.Cancel(); Hide()`) to keep the webview warm.

On macOS, `main.go` overrides Wails' default `applicationShouldHandleReopen` listener (which shows *every* hidden window — see `pkg/application/events_common_darwin.go`) by registering an application event hook that cancels the event and shows only the main window. Without this, clicking the dock icon would resurrect the hide-on-close Settings window alongside the main one.

The main window is **hidden** on close (the `WindowClosing` hook calls `e.Cancel(); window.Hide()`). The user reaches "really quit" through the tray → Quit menu entry.

## Localisation (i18n)

The locale tree under `client/ui/i18n/locales/` is the single source of truth for both Go (tray, OS notifications) and React (every user-facing string). It sits next to the Go `i18n` package (the tray's consumer) so a single JSON tree drives both surfaces. Layout: `_index.json` lists shipped languages (`code` / `displayName` / `englishName`); `<code>/common.json` per language. `en/common.json` must exist (the `Bundle` loader hard-fails without it); languages listed in `_index.json` without a bundle are skipped with a warning. Placeholders are single-braced (`"Install version {version}"`) — Go substitutes via `Bundle.Translate(lang, key, "name", value, ...)`; React uses i18next with `interpolation: { prefix: "{", suffix: "}" }`.

Adding a language: drop a `<code>/common.json` under `client/ui/i18n/locales/`, append a row to `_index.json`, rebuild. Go reads the tree via `//go:embed all:i18n/locales` in `client/ui/main.go`; Vite reads it via the `../../../i18n/locales/*/common.json` glob in `frontend/src/lib/i18n.ts`, with `server.fs.allow` in `vite.config.ts` whitelisting the parent dir so the dev server can serve files outside `frontend/`.

Package layout:
- `client/ui/i18n/` — pure `LanguageCode` / `Language` / `Bundle` loader. No Wails / no daemon. Reads the tree from an `fs.FS` passed in by `main.go`.
- `client/ui/preferences/` — `Store` persists `UIPreferences{language}` to `os.UserConfigDir()/netbird/ui-preferences.json` (per-OS-user, shared across daemon profiles). Validates against an injected `LanguageValidator` (`*i18n.Bundle`). No file → in-memory default `en`, persisted on first `SetLanguage`. Broadcasts via in-process pub/sub + optional Wails event emitter.
- `services/i18n.go` + `services/preferences.go` — Wails facades. Preferences emits `netbird:preferences:changed` (payload `{language}`) on every `SetLanguage`.

Key conventions: `tray.*` / `notify.*` (Go-side), `common.* / connect.* / nav.* / profile.* / settings.* / update.* / browserLogin.* / sessionExpiration.* / peers.*` (frontend). Keep keys stable — renames cascade everywhere.

## Linux tray support

The in-process `StatusNotifierWatcher` + XEmbed host that lets the tray work on minimal WMs is detailed in `LINUX-TRAY.md` (sibling). Touch that doc when modifying `tray_watcher_linux.go` / `xembed_host_linux.go` / `xembed_tray_linux.{c,h}`.

**Legacy `-tags gtk3` build:** Wails v3 defaults to GTK4/WebKitGTK 6.0; the legacy GTK3/WebKit2GTK 4.1 path (`-tags gtk3`, for Ubuntu 22.04 / Debian 12 / RHEL 9 / Fedora ≤39, removed upstream in Wails v3.1) is shipped as a second `netbird-ui` package built via `EXTRA_TAGS=gtk3` / a separate goreleaser lane. `xembed_host_linux.go` + `xembed_tray_linux.{c,h}` are GTK4-only (`//go:build … && !gtk3`); on gtk3 builds `xembed_host_gtk3_linux.go` stubs them out (`xembedTrayAvailable()` → false), so the minimal-WM XEmbed fallback is **absent on gtk3** (tray still works on SNI-capable desktops). Keep the C files' `//go:build` constraints in sync with the Go file.

## Wails Dialogs (frontend, `@wailsio/runtime`)

The app no longer uses native `@wailsio/runtime` `Dialogs.*` message boxes — errors go through the custom Error window (see below), confirmations through the in-app `useConfirm()` modal. `WAILS-DIALOGS.md` (sibling) is retained only as reference for the native API surface and the Go-side frameless-window pattern, should a native file picker (`OpenFile`/`SaveFile`) ever be needed.

## Conventions in this codebase

### Errors → custom Error window

User-actionable operation failures (config save, profile switch, debug bundle, update, login, etc.) surface via the frontend `errorDialog({Title, Message})` helper in `frontend/src/lib/dialogs.ts`, which opens the custom always-on-top **Error** auxiliary window (`WindowManager.OpenError`, `/#/dialog/error` — see the Auxiliary windows section). Use an action-named title — "Save Settings Failed", "Switch Profile Failed", not "Error" / "Something went wrong" (the window already shows a red error icon). The name `errorDialog` and its `{Title, Message}` shape are unchanged from when it wrapped the native `Dialogs.Error`, so call sites were untouched; the native `Dialogs.Error`/`Warning`/`Info`/`Question` wrappers and the Windows `Detached` workaround were removed (the native MessageBox could wedge the main window's close button — see the Error-window note). Confirmations use the in-app `useConfirm()` modal (`contexts/DialogContext.tsx`), which resolves to a boolean.

**Skip dialogs entirely** for: inline form validation (`Input.tsx`, URL-format checks — too heavy for keystroke feedback); transient link errors on the dashboard (flap in/out with daemon — use an inline indicator); "partial success" notes inside an otherwise-OK flow (e.g. "bundle saved but upload failed" stays inline). The install-progress window owns its own error UI in-place (timeout/canceled/failed phases) — no error dialog needed there.

### OS notifications

The tray uses Wails' built-in `notifications` service. One `notifications.NotificationService` is created in `main.go` and passed into `TrayServices.Notifier`. Notification IDs are prefixed for coalescing: `netbird-update-<version>`, `netbird-event-<id>`, `netbird-tray-error`, `netbird-session-expired`. Notifications are gated by the user's "Notifications" toggle (cached in `Tray.notificationsEnabled`, seeded from `Settings.GetConfig` at boot). `Severity == "critical"` events bypass the gate, mirroring the legacy Fyne `event.Manager`.

### Profile switching invariants

`ProfileSwitcher.SwitchActive` is the only switch path on the TS side — `ProfileContext.switchProfile` is the single TS wrapper, and `modules/profiles/ProfilesTab.tsx` + the header `ProfileDropdown` both go through it. The Go side captures `prevStatus`, drives the optimistic-Connecting paint via `Peers.BeginProfileSwitch`, mirrors into the user-side `profilemanager`, and conditionally fires Down/Up per the reconnect-policy table above.

**Never call `Connection.Up` on an Idle/NeedsLogin daemon** — the daemon's internal 50s `waitForUp` blocks until `DeadlineExceeded`. `Connection.Up` from the frontend is reserved for the explicit Connect button (`ConnectionStatusSwitch.connect`) and the post-SSO resume inside `startLogin`; the gating for profile-switch reconnects lives Go-side in `ProfileSwitcher.SwitchActive`.

## Build / dev tasks

`task dev` (Wails dev, live reload), `task build` (prod build for the current OS, dispatches to `build/{darwin,linux,windows}/Taskfile.yml`), `task build:server` / `run:server` / `build:docker` / `run:docker` (server-mode variants in `build/Taskfile.yml`). **No** `task generate:bindings` alias — run `wails3 generate bindings -clean=true -ts` directly from this directory. CLI flags + log-target semantics are documented in the `main.go` bullet under "Layout".

Both `windows:build` and `windows:build:console` (the latter outputs `bin/netbird-ui-console.exe` linked against the console subsystem, so Go stdout/stderr/logrus print to the launching terminal) honour `DEV=true`, which drops the `-tags production` flag. The `production` tag is what disables the WebKit/WebView2 DevTools inspector — so `DEV=true` is the only way to get a Windows binary where the frontend JS console is reachable (right-click → Inspect / F12). Cross-compile from Linux with `CGO_ENABLED=1 task windows:build:console DEV=true`.

## Useful references
- `WAILS-DIALOGS.md` (sibling) — full `@wailsio/runtime` `Dialogs` API + per-OS behaviour + frameless-window pattern.
- `LINUX-TRAY.md` (sibling) — StatusNotifierWatcher + XEmbed host details.
- `frontend/WAILS-API.md` — frontend-facing binding signatures and model shapes.
- Wails v3 dialog docs: https://v3.wails.io/features/dialogs/message/ and https://v3.wails.io/features/dialogs/custom/ (may 403 from some clients).
- Wails v3 multiple-windows guidance: https://v3.wails.io/learn/multiple-windows/
- Authoritative TS signatures: `frontend/node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails examples: https://github.com/wailsapp/wails/tree/master/v3/examples/dialogs
