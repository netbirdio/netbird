# NetBird Wails UI — Frontend Working Notes

This is the React/TS frontend for the Wails v3 desktop UI. It runs inside the main Wails webview plus two auxiliary windows (`/#/settings` and `/#/browser-login`) opened by Go (`services/windowmanager.go`). For Go-side conventions and the daemon gRPC layer see `../CLAUDE.md`.

> **Keep these notes current.** When working in this directory with Claude, update this file whenever you change conventions, rename a context/provider, shift the route table, add or remove a top-level dependency, or introduce a new cross-cutting feature (i18n, theming, telemetry, etc.). The aim is that a cold-start agent can orient itself from these notes without re-deriving the codebase.

> **Work in progress.** Big chunks of the UI are still mocked, prototyped, or duplicated across screens that pre-date the current AppLayout. Anything marked "prototype" / "mocked" / "legacy" below should be assumed half-wired. The polished surface today is: the main connect toggle, the Settings window, the debug-bundle flow, the auto-update overlay, and the profile selector. Everything else is in flight.

## Stack & tooling

React 18 + TS 5.7 (`strict`, `noImplicitAny: false`) + Vite 6 + Tailwind 3 (`darkMode: "class"`) + Radix primitives + i18next + `@wailsio/runtime`. React Router v7 `HashRouter` (Wails serves a static bundle). pnpm only — `package.json` is authoritative for deps and scripts. Class merging: `cn(...)` in `src/lib/cn.ts`. framer-motion is used only by `NetBirdConnectToggle`. `task dev` from `client/ui/` is the canonical dev entry point — it runs Vite on `WAILS_VITE_PORT || 9245`.

## Path aliases & bindings

`@/*` → `src/*`, `@bindings/*` → `bindings/github.com/netbirdio/netbird/client/ui/*` (set in both `tsconfig.json` and `vite.config.ts`). Canonical imports: `from "@bindings/services"` (functions) and `from "@bindings/services/models.js"` (types).

`bindings/` is gitignored and fully generated. A fresh clone has no `bindings/` on disk, so `pnpm typecheck` fails until you run `pnpm bindings` (or `wails3 generate bindings -clean=true -ts` from `client/ui/`) once. `wails3 dev` regenerates on its own.

## Routing (app.tsx)

`HashRouter` with the following routes:

| Path | Component | Layout | Where it opens |
|---|---|---|---|
| `/` |  `MainPage` (modules/main/) | `AppLayout` | Main window default route |
| `/dialog/browser-login` | `LoginWaitingForBrowserDialog` (modules/login/) | none | Auxiliary window (Go `WindowManager.OpenBrowserLogin`) |
| `/dialog/install-progress` | `UpdateInProgressDialog` (modules/auto-update/) | none | Auxiliary window (Go `WindowManager.OpenInstallProgress(version)`, always-on-top). Owns the install-result polling + 5s daemon-down-grace; calls `Update.Quit()` on success. Opened by `ClientVersionContext.triggerUpdate` (enforced user-driven branch) and on the `installing` flip from `netbird:update:state` (force-install branch). |
| `/dialog/session-expired` | `SessionExpiredDialog` (modules/session/) | none | Auxiliary window (Go `WindowManager.OpenSessionExpired`, always-on-top) |
| `/dialog/session-about-to-expire` | `SessionAboutToExpireDialog` (modules/session/) | none | Auxiliary window (Go `WindowManager.OpenSessionAboutToExpire(seconds)`, always-on-top, mm:ss countdown via `?seconds=`) |
| `/dialog/welcome` | `WelcomeDialog` (modules/welcome/) | none | Auxiliary window (Go `WindowManager.OpenWelcome`). First-launch onboarding — opened from `main.go`'s `ApplicationStarted` hook only when `prefStore.Get().OnboardingCompleted` is false. Two-step state machine: tray-screenshot pitch → Cloud-vs-self-hosted segmented control (conditional, see `shouldShowManagementStep`). Continue calls `Preferences.SetOnboardingCompleted(true)`, then `WindowManager.OpenMain()`, then `WindowManager.CloseWelcome()`. |
| `/settings` |  `SettingsPage` (modules/settings/) | `AppLayout` | Auxiliary window (Go `WindowManager.OpenSettings(tab)`). Inherits the shared provider stack from `AppLayout`; the page itself adds the draggable strip + tabs. The `Profiles` tab (`modules/profiles/ProfilesTab.tsx`, `UserCircle` icon, between Security and SSH) lists profiles in a table with Deregister/Delete in a per-row kebab and an Add Profile button. The header `ProfileDropdown`'s "Manage Profiles" entry calls `OpenSettings("profiles")`. The window stays at `/#/settings` for its whole lifetime — no `SetURL` between opens, so `AppLayout`'s providers never remount. Tab is React local state, driven by the `netbird:settings:open` event Go emits before `Show`. Reset-to-General on close is handled in React via `document.visibilitychange` (Page Visibility API), which fires *before* WebKit throttles the hidden page, unlike Wails events from the Go close hook which race `Hide` and leave the previous tab visible for one frame on the next open. |
| `*` | `<Navigate to="/">` | `AppLayout` | Catch-all |

In `app.tsx` the four dialog routes are nested under a parent `<Route path="dialog">` so the table reads as a tree, not a flat list. The Go side mirrors the prefix — `WindowManager` opens windows at `/#/dialog/<name>`. The `dialog` group has no shared layout component; it's purely a URL grouping.

`AppLayout` is the only in-window layout. It mounts the shared provider stack (`DialogProvider → StatusProvider → ProfileProvider → DebugBundleProvider → ClientVersionProvider`) inside a `relative flex h-full flex-col` shell and renders `<Outlet/>`. `DialogProvider` is outermost (and outside the daemon-availability gate) so `useConfirm()` works everywhere regardless of daemon state. Both `Main` (route `/`) and `Settings` (route `/settings`) sit under it. Order matters: `SettingsContext` depends on `ProfileContext`, `ClientVersionContext` reads `StatusContext` events. `StatusProvider` (in `contexts/StatusContext.tsx`) owns the single `Peers.Get` + `netbird:status` subscription, exposes `{ status, error, refresh, isReady, isDaemonAvailable, isDaemonUnavailable }`, **and only renders its children when the daemon is reachable** — until the first `Peers.Get` resolves and on `DaemonUnavailable` it short-circuits to just the `<DaemonUnavailableOverlay/>` (also owned by the provider). The consequence: every context downstream (`ProfileProvider`, `DebugBundleProvider`, `ClientVersionProvider`) can assume the daemon is reachable at mount time — no per-context `useStatus` gating. When the daemon flips back to unavailable the whole downstream subtree unmounts and remounts fresh once it returns. `ClientVersionProvider` no longer paints any inline overlay; install progress lives in its own auxiliary window (see `/install-progress` route).

Page-specific chrome lives next to the page, not in the layout:
- **`pages/main/Main.tsx`** owns the `Header`, `ViewModeProvider`, and `NavSectionProvider`. All three are main-window-only:
  - `Header` reads `useViewMode` (view-mode dropdown) and `useClientVersion` (update badge).
  - `ViewModeProvider` wraps the whole of `Main` because both `Header` and `MainBody` read view mode. It calls `Window.SetSize` on the current Wails window, so it must not be visible to the Settings window.
  - `NavSectionProvider` is mounted only inside the advanced-mode branch (`MainBody → AdvancedRightPanel`) — the default-mode view has no Peers/Resources/Exit Nodes tabs and no consumer of `useNavSection`. Default mode therefore skips the provider entirely.
  - `Header.tsx`, `Navigation.tsx`, and `ConnectionStatusSwitch.tsx` are siblings of `Main.tsx` in `pages/main/` because nothing else uses them.
- **`pages/Settings.tsx`** owns the `h-12` `wails-draggable` strip at the top (so the macOS traffic-light buttons that float over the `MacTitleBarHiddenInset` window don't overlap content), then renders the vertical tabs — no view-mode, no nav, no header.

## Directory layout (src/)

- `app.tsx` — root render + route table. The canonical registry of every route; scan this file to enumerate pages.
- `layouts/AppLayout.tsx` — the router-level layout. Mounts the shared provider stack (`StatusProvider → ProfileProvider → DebugBundleProvider → ClientVersionProvider`) and renders `<Outlet/>`. (`layouts/` also holds `AppRightPanel.tsx`, see below.)
- `modules/<feature>/` — every feature owns its own folder: page entry (named `<Feature>Page.tsx`), local components, and everything else it needs:
  - `modules/main/` — `MainPage.tsx` + main-window chrome (`Header.tsx`, `ConnectionStatusSwitch.tsx`).
    - `modules/main/advanced/` — advanced-mode-only surfaces. `Navigation.tsx` plus the three feature sub-modules whose tabs only render here: `peers/`, `networks/`, `exit-nodes/`.
  - `modules/settings/` — `SettingsPage.tsx`, shared helpers (`SettingsSection.tsx`, `SettingsNavigation.tsx`, `SettingsSkeleton.tsx`), and all tab files flat (`SettingsGeneral`, `SettingsNetwork`, `SettingsSSH`, `SettingsSecurity`, `SettingsAdvanced`, `SettingsTroubleshooting`, `SettingsAbout`, `SettingsAccent`). `ManagementServerSwitch` and `LanguagePicker` are shared in `components/`; `useManagementUrl` is in `hooks/`.
  - `modules/login/` — `LoginWaitingForBrowserDialog.tsx` (the SSO browser-wait window).
  - `modules/session/` — `SessionExpiredDialog.tsx` and `SessionAboutToExpireDialog.tsx` (session lifecycle dialog windows).
  - `modules/auto-update/` — `UpdateInProgressDialog.tsx`, `UpdateBadge.tsx`, `UpdateVersionCard.tsx`. Context lives in `contexts/`.
  - `modules/profiles/` — `ProfileAvatar.tsx`, `ProfileDropdown.tsx`, `ProfileCreationModal.tsx`, `ProfilesTab.tsx`. Context lives in `contexts/`.
  - `modules/welcome/` — first-launch onboarding dialog window. `WelcomeDialog.tsx` is the orchestrator (state machine over `tray → management → finish`); each step has its own file (`WelcomeStepTray`, `WelcomeStepManagement`). The `management` step is conditionally rendered: only when active profile is `"default"`, the profile email is empty, and the current management URL is cloud-default-or-empty (`shouldShowManagementStep` in the orchestrator). Reachability of self-hosted URLs is a soft warning via `hooks/useManagementUrl.ts checkManagementUrlReachable`; the user can re-click Continue to proceed despite a failed check. No login step — once the dialog closes, the user lands in the main window and clicks Connect there, which runs the connect toggle's local `startLogin` orchestrator.

  Note: there's no `modules/daemon-status/` or `modules/debug-bundle/` folder. The daemon-status overlay is a generic presentational component (`components/empty-state/DaemonUnavailableOverlay.tsx`) and `useDebugBundle` is inlined into `contexts/DebugBundleContext.tsx` — both folders would be empty otherwise.
- `contexts/` — every React context in the app lives here as a flat file (`StatusContext`, `ProfileContext`, `DebugBundleContext`, `ClientVersionContext`, `SettingsContext`, `NetworksContext`, `PeerDetailContext`, `ViewModeContext`, `NavSectionContext`, `DialogContext`). Single mental model: "where is the X context? `contexts/XContext.tsx`."
- `components/` — presentational primitives, no domain coupling. Grouped by family:
  - `components/buttons/` — `Button`, `IconButton`.
  - `components/inputs/` — `Input`, `SearchInput`.
  - `components/dialog/` — `Dialog`, `DialogActions`, `DialogDescription`, `DialogHeading`, `ConfirmDialog` (window-based dialog layout primitive), `ConfirmModal` (in-app Radix confirmation modal; usually driven via `useConfirm()` rather than rendered directly).
  - `components/switches/` — `SwitchItem`, `SwitchItemGroup`, `ToggleSwitch`, `FancyToggleSwitch`.
  - `components/typography/` — `Label`, `HelpText`.
  - `components/empty-state/` — `EmptyState`, `NoResults`, `NotConnectedState`.
  - Flat at root: `Badge.tsx`, `CopyToClipboard.tsx`, `DropdownMenu.tsx`, `SquareIcon.tsx`, `Tooltip.tsx`, `VerticalTabs.tsx` (one-of-a-kind primitives).
- `layouts/` — `AppLayout.tsx` (the only router-level layout) plus the shared content shell `AppRightPanel.tsx` used by both `MainPage` and `SettingsPage`.
- `hooks/` — reusable React hooks (`useAutoSizeWindow.ts`, `useKeyboardShortcut.ts`).
- `lib/` — pure utilities (no JSX, no React state): `cn.ts`, `errors.ts`, `formatters.ts` (byte/latency/relative-time helpers), `i18n.ts`, `welcome.ts`. Management-URL utilities (`CLOUD_MANAGEMENT_URL`, URL regex, `isValidManagementUrl`, `normalizeManagementUrl`, `isCloudManagementUrl`, `checkManagementUrlReachable`) live alongside the hook in `hooks/useManagementUrl.ts`. The SSO orchestrator (`startLogin` + `EVENT_TRIGGER_LOGIN` / `EVENT_BROWSER_LOGIN_CANCEL`) lives at module scope inside `modules/main/MainConnectionStatusSwitch.tsx` — the only caller.
- `assets/` — fonts, logos, flags. `screens/` is a residual legacy bucket — don't add new code there.

## Wails event bus

Subscribe with `Events.On(name, handler)`. The handler receives `{ data: <typed payload> }`. The event name strings live next to their usage (no central registry on the TS side).

| Event name (string) | Payload | Emitted by | Consumed by |
|---|---|---|---|
| `netbird:status` | `Status` | `services/peers.go statusStreamLoop` | `contexts/StatusContext` (`useStatus`) |
| `netbird:event` | `SystemEvent` | `services/peers.go toastStreamLoop` | Not currently subscribed on the TS side — Status is read via `useStatus().status.events` instead. The tray (Go) consumes it for OS notifications. |
| `netbird:profile:changed` | `ProfileRef` | `services/profileswitcher.go SwitchActive` | `contexts/ProfileContext` refreshes so a tray-initiated switch paints in the React UI. |
| `netbird:update:available` | `UpdateAvailable` | `services/peers.go fanOutUpdateEvents` | Not directly subscribed on the TS side; `ClientVersionContext` derives `updateVersion` from `status.events` metadata instead. |
| `netbird:update:progress` | `UpdateProgress` | same | Drives the tray. UI side: `WindowManager.OpenInstallProgress` is what opens the install window; the React listener for `installing` flips lives in `ClientVersionContext`. |
| `netbird:update:state` | `UpdateState` | `services/peers.go fanOutUpdateEvents` + the updater's `progress_window:show` translator | `modules/auto-update/ClientVersionContext` — single source of truth for `updateAvailable / version / enforced / installing`. |
| `browser-login:cancel` | (no payload) | `BrowserLogin` page (frontend) when user clicks Cancel **or** Go `services/windowmanager.go` when user closes the BrowserLogin window | `pages/main/ConnectionStatusSwitch.tsx`'s `startLogin()` to abort the in-flight `WaitSSOLogin` |
| `trigger-login` | (no payload) | Reserved (`services.EventTriggerLogin`); `pages/main/ConnectionStatusSwitch.tsx` subscribes and runs `startLogin()` when fired. No Go-side emitter today. |
| `netbird:settings:open` | `string` (tab id, e.g. `"general"`, `"profiles"`) | `services/windowmanager.go OpenSettings` (before Go calls `Show`) | `modules/settings/SettingsPage.tsx` — just `setActive(e.data)`. Reset-on-close is **not** driven by this event — see the `visibilitychange` listener in the same file. |

If you wire a new daemon-event subscriber on the TS side, prefer subscribing once at the context level rather than per-screen — the Wails event bus is process-wide and each `Events.On` adds an emit-time fan-out.

## Contexts and state

State that crosses screens / windows lives in context. Each provider is mounted exactly once inside `AppLayout` or `SettingsLayout`.

- **`useStatus`** (`contexts/StatusContext.tsx`) — `{ status, error, refresh, isReady, isDaemonAvailable, isDaemonUnavailable }`. The provider owns a single `Peers.Get()` + `netbird:status` subscription and renders `<DaemonUnavailableOverlay/>`. `refresh()` after Connect/Disconnect to dodge a few hundred ms of event-stream lag. Other contexts (e.g. `ProfileContext`) read the boolean flags to skip RPCs while the daemon socket is down.

- **`ProfileContext`** (`modules/profiles/`) — `username`, `activeProfile`, `profiles`, plus `refresh` / `switchProfile` / `addProfile` / `removeProfile` / `logoutProfile`. `switchProfile` delegates to `ProfileSwitcher.SwitchActive` (the Go-side single source of truth — drives the optimistic-Connecting paint and `Peers` suppression). The other methods are thin wrappers over `Profiles.*` / `Connection.Logout` plus a `refresh()`.

- **`SettingsContext`** (`modules/settings/`) — `setField` / `saveField` / `saveFields` / `saveNow` over `SettingsSvc.GetConfig|SetConfig` with 400ms debounce. Renders `<SettingsSkeleton/>` while `config === null` so tabs never see null. **PSK mask quirk:** `GetConfig` returns existing PSKs as `"**********"`; sending the mask back round-trips it into storage and `wgtypes.ParseKey` fails on the next connect. `save` drops the field when it equals `"**********"`.

- **`DebugBundleProvider` + `useDebugBundle`** (`contexts/DebugBundleContext.tsx`) — stages: `idle → preparing-trace → reconnecting → capturing → restoring-level → bundling → uploading → done`. Cancellable via `AbortController` at any stage; cancel restores the original log level best-effort. Wrapped in a context so the troubleshooting tab keeps stage across navigation. Upload URL is the hardcoded `NETBIRD_UPLOAD_URL`.

- **`ClientVersionContext`** (`modules/auto-update/`) — seeds from `Update.GetState()` and subscribes to `netbird:update:state`; exposes `{ updateAvailable, updateVersion, enforced, installing, triggerUpdate, updating }`. **Three branches**:
  1. `available && !enforced` — download-only. `UpdateVersionCard` shows "Version X is available for download" + "Download installer" → opens GitHub releases.
  2. `available && enforced && !installing` — user-driven enforced. `UpdateVersionCard` shows "Version X is available for install" + "Install now" → `triggerUpdate` opens `/install-progress` window then calls `Update.Trigger()`.
  3. `available && enforced && installing` — daemon already installing (force-install). The `installing` flip auto-opens `/install-progress` via `WindowManager.OpenInstallProgress`.

### Default/Advanced view + no client-side persistence

The `ViewModeProvider` (`src/lib/viewMode.tsx`, mounted in `AppLayout`) owns a `viewMode: "default" | "advanced"` state and is consumed by `Header.tsx`'s "more" dropdown via `useViewMode()`. `setViewMode` updates state, calls `Window.SetSize(width, <live frame height>)`, and persists via `Preferences.SetViewMode`. Widths live in `VIEW_WIDTH` at the top of `viewMode.tsx`: Default = 380, Advanced = 900. **The height is intentionally not asserted** — we read the current frame height via `Window.Size()` and pass it back, because Wails' macOS `windowSetSize` is implemented as `setFrame:` (frame, incl. ~28px title bar) while the initial `windowNew` uses `initWithContentRect:` (content). Passing a constant 640 would chop ~28px off the content area on the first switch and visually shift everything inside (the connect toggle is `justify-center` in a column that depends on the parent's height). Reusing the live height keeps content area stable across all switches. The view is persisted user-side (see Go-side `preferences.Store`): `main.go` opens the main window at the saved width so the user never sees a 380→900 flash on launch, and the provider hydrates its React state from `Preferences.Get()` in a mount effect (no resize triggered there — Go already sized it). **No `localStorage` / `sessionStorage` / cookies anywhere in the frontend** — persistence is the Go side's job (settings → `SetConfig`, language → `Preferences.SetLanguage`, view mode → `Preferences.SetViewMode`).

## Localisation (i18n)

Bootstrap lives in `src/lib/i18n.ts` and is awaited before render in `app.tsx`. It reads the current language from `Preferences.Get()`, statically imports every bundle JSON (`en/common.json`, `de/common.json`, `hu/common.json` today) from the shared tree at `client/ui/i18n/locales/` (sibling of the Go i18n package — same JSON drives both tray and React), initialises i18next with `fallbackLng: "en"` and `interpolation: { prefix: "{", suffix: "}" }`, and subscribes to the `netbird:preferences:changed` Wails event so a flip from any window (tray, settings, another renderer) calls `i18next.changeLanguage` here.

**First-run browser-language detection.** When no preferences file exists, `Preferences.Get()` returns `language: ""` (the Go-side "unset" signal — `preferences.Store` no longer pre-fills a default). `initI18n` walks `navigator.language` + `navigator.languages`, lowercases each tag, and picks the first base code (`de` from `de-DE`) that has a shipped bundle — then calls `Preferences.SetLanguage(detected)` fire-and-forget so the next launch reads it back without re-detecting. If nothing matches (or the store is unreachable) the session falls through to `en`. From the second launch onward, the Go-side persisted value wins and detection is skipped. The tray (`localizer.go`) treats empty as English via its own fallback to `i18n.DefaultLanguage` so the first menu render before SetLanguage round-trips is still readable.

The frontend deliberately uses **no `localStorage` / `sessionStorage` / cookies anywhere** — persistence is the Go side's job (settings via `SettingsContext.save → SetConfig`, language via `Preferences.SetLanguage`). The previous wide-panel and settings-tab persistence experiments were removed; every window opens at its baseline state.

**Usage in components.** Default to the hook:

```ts
import { useTranslation } from "react-i18next";
const { t } = useTranslation();
return <span>{t("settings.tabs.general")}</span>;
// with placeholders:
t("update.card.versionAvailable", { version: updateVersion })
```

For strings outside React (event handlers in modules, `Dialogs.Error` titles set from `useDebugBundle`, `useManagementUrl`, `ProfileContext`, `SettingsContext`) import the i18next instance directly:

```ts
import i18next from "@/i18n";
await Dialogs.Error({ Title: i18next.t("settings.error.saveTitle"), Message: ... });
```

**Confirm dialogs.** `Dialogs.Warning` resolves with the **button label string** — not an index. After translation, those labels change per language. Pin the label into a variable so the comparison stays correct:

```ts
const confirmLabel = t("profile.delete.message"); // wrong example — show your real key
const cancelLabel = t("common.cancel");
const result = await Dialogs.Warning({ Title, Message, Buttons: [
  { Label: cancelLabel, IsCancel: true },
  { Label: confirmLabel, IsDefault: true },
]});
if (result !== confirmLabel) return;
```

Compare against the variable, never against an English literal.

**Bundle files.** Keys live in `client/ui/i18n/locales/<code>/common.json` as a flat key→string map (`"settings.tabs.general": "General"`). Placeholders use single braces: `"Install version {version}"`. Adding a key: add to `en/common.json` first (the fallback), then every other locale. Missing keys fall back to English; if even that misses, i18next returns the key itself so the gap is visible in the UI rather than blank.

**Adding a language.** Drop `client/ui/i18n/locales/<code>/common.json` and append the row to `client/ui/i18n/locales/_index.json`. Also drop the matching `<code>.svg` into `src/assets/flags/1x1/` — source those from the NetBird dashboard repo's same-name folder so the icon set stays consistent: https://github.com/netbirdio/dashboard/tree/main/public/assets/flags/1x1 . **Only check in flags for languages we actually ship** — `LanguagePicker.tsx` eager-globs that directory at build time, so every SVG in it gets bundled into the Wails app whether referenced or not. `src/lib/i18n.ts` discovers bundles via `import.meta.glob('../../../i18n/locales/*/common.json', { eager: true })` (the locales tree lives outside `frontend/`, so `vite.config.ts` whitelists the parent dir under `server.fs.allow`), so no code change is needed to wire the new locale in. Vite still inlines each bundle at build time, same chunk shape as static imports. The Go side reads the same tree (embedded via `client/ui/main.go`'s `embed.FS`), so the tray menu localises automatically off the same files.

**Language picker.** `src/components/LanguagePicker.tsx` is mounted inside the Language section of `SettingsGeneral.tsx`. It populates from `I18n.Languages()` (matches `_index.json`) and calls `Preferences.SetLanguage(code)` on selection. The preference write triggers `netbird:preferences:changed`, which both the local i18next instance and every other open window listen to.

**What gets translated.** Every user-facing string in the polished AppLayout/Settings/Update/BrowserLogin/SessionExpired/Peers surfaces. Don't add hard-coded user-facing English to new code — add the key, then `t()`. Internal log strings, dev-only forced-state strings in `ClientVersionContext`, and the `Update failed` fallback fed into `classifyError()` (which then renders a translated description) are not translated.

## Login flow (`startLogin` in `ConnectionStatusSwitch.tsx`)

The SSO flow is centralised in a module-level `startLogin()` with a `loginInFlight` guard so a double-click can't fire two concurrent flows. Sequence:

1. `Connection.Login({})` with empty fields — Go fills in active profile + OS user.
2. If the daemon needs SSO (`needsSsoLogin`):
   - `WindowManager.OpenBrowserLogin(uri)` opens the auxiliary "waiting for sign-in" window (Hidden until React mounts and `useAutoSizeWindow` calls `Window.Show`).
   - `LoginWaitingForBrowserDialog` mounts, gets shown by `useAutoSizeWindow`, then fires `Connection.OpenURL(uri)` from its mount effect — opens the verification page in the system browser (honors `$BROWSER`). Done from the dialog (not `startLogin`) so the browser doesn't race the still-hidden NetBird popup and land on top.
   - `Promise.race(WaitSSOLogin, EVENT_BROWSER_LOGIN_CANCEL)` — whichever resolves first.
   - On cancel: `Connection.Down()` to dislodge the daemon's pending `WaitSSOLogin` so the next Login starts fresh (see `services/connection.go:74`).
3. `Connection.Up({})` to bring the new session up.

Errors that aren't cancellations surface via `Dialogs.Error`.

This is the only SSO entry point used by the polished Main UI. There is no `/login` route in `app.tsx`; if you add one, wire it up here rather than introducing a parallel SSO flow.

## Components

`src/components/` holds presentational primitives (no daemon RPCs, no router) — see the directory listing. Settings rows use `FancyToggleSwitch` inside `<SectionGroup title=…>` (section-group dimming via `disabled` → greyed + `pointer-events-none`). In-app modals use the Radix `Dialog` primitive in the main webview; the two auxiliary OS windows (Settings, BrowserLogin) are created Go-side via `WindowManager`.

## Dialogs convention

**Always go through `src/lib/dialogs.ts`** — `errorDialog` / `warningDialog` / `infoDialog` / `questionDialog`, not `Dialogs.*` from `@wailsio/runtime` directly. These thin wrappers force `Detached: true` on Windows (no-op elsewhere, and any caller-supplied `Detached` wins). A native Windows `MessageBox` attached to a parent window sets that window `WS_DISABLED` for its lifetime and re-enables it on dismissal; when the parent is the main window — whose `WindowClosing` hook hides instead of closes (`main.go`) — the enable/hide sequence races and leaves the window unable to process its close (X) button afterwards. Detaching gives the box a NULL owner so no window is ever disabled. macOS keeps the attached sheet-style presentation. The wrappers re-export the same option shape, so call sites are otherwise unchanged.

Errors → `errorDialog` with action-named title ("Save Settings Failed", not "Error"). For **confirmations inside an app window** (the polished surfaces), prefer the in-app `useConfirm()` from `contexts/DialogContext.tsx` over the native `warningDialog` — `const ok = await confirm({ title, description, confirmLabel, danger? })` resolves to a boolean. It renders a single shared `ConfirmModal` (left-aligned title + multi-line description, Cancel/confirm footer) mounted at the provider level, so call sites don't each wire up their own modal + open state. Used by the Profiles tab (switch/deregister/delete) and the management-server cloud switch (`useManagementUrl`). Reserve the native `warningDialog` (compare against the **Label string**, not an index) for confirmations raised outside a normal app window (tray-driven flows, etc.). **Skip** native dialogs for inline form validation, transient link errors on the dashboard, and "partial success" notes inside an otherwise-OK flow. Full API + per-OS notes in `../WAILS-DIALOGS.md`; full convention rationale in `../CLAUDE.md`.

## Tailwind tokens

Defined in `tailwind.config.ts`. `nb-gray` is the neutral palette (background = `nb-gray-950`); `netbird` is brand orange (`#f68330`). The Flowbite-style `gray`/`red`/`yellow`/`...` palettes are legacy — only use them inside `screens/*`; new code sticks to `nb-gray` + `netbird` + semantic dot colors (`green-500`, `red-500`, `yellow-500`). `bg-conic-netbird` and the `pulse-reverse` / `spin-slow` / `ping-slow` keyframes are used only by `NetBirdConnectToggle`. Fonts: Inter Variable (sans) + JetBrains Mono Variable (mono), shipped under `src/assets/fonts/`.

## Wails-specific quirks

- **Window dragging.** Use class `wails-draggable` on regions that should drag the OS window (the Header, the SettingsLayout title strip, dialog wrappers like `ConfirmDialog`). Use `wails-no-draggable` on interactive children inside a draggable region (buttons, inputs) — otherwise the drag swallows their click.
- **Webview asset access.** Background images / fonts go through Vite at build time, so reference them with `import url from "@/assets/.../foo.svg"`. The Wails dev server proxies `/` to Vite, but absolute filesystem paths won't work in either dev or prod.
- **`Window.SetSize(w, h)`.** Called from `viewMode.tsx`'s `setViewMode` when the user flips the view-mode dropdown. Width comes from `VIEW_WIDTH` (380 / 900); height is read fresh from `Window.Size()` and re-passed, because Wails' macOS `windowSetSize` treats height as the frame (including title bar) while initial window creation treats it as content — re-asserting a constant would shrink the content area by one title-bar height. See the "Default/Advanced view" section above.
- **`Browser.OpenURL(url)`.** Used by `SettingsAbout` for legal links and by the `BrowserLogin` page's "Try again". Has a `window.open` fallback in `SettingsAbout` for the case where Wails refuses (non-http schemes are rejected by Wails).

## Things in flight (don't be surprised by)

- **`screens/Peers.tsx`** uses live `Peers.Get` data. **`modules/peers/Peers.tsx`** uses `mockPeers.ts`. The mock-driven one is mounted under `Main.tsx`'s `AppRightPanel` and is what the user sees today; the real-data one isn't wired into the route table.
- **`modules/session/SessionExpiredDialog.tsx`** and **`modules/session/SessionAboutToExpireDialog.tsx`** are the always-on-top auxiliary windows. No triggers wired today — a daemon-status hook (status `SessionExpired`, plus a future "about-to-expire" signal) will drive them later. Sign-in / Stay-connected emit `EventTriggerLogin` so the main window's `startLogin()` orchestrator handles the SSO flow; Logout uses `Connection.Logout({profileName, username})`.

## Wails Go API reference

Full per-service binding signatures, push-event payloads, and model field shapes live in `WAILS-API.md` (sibling). Every service method returns `$CancellablePromise<T>` — `await` and ignore `.cancel()` in practice. Regenerate bindings via `pnpm bindings` after any Go-side change.

## Useful references

- `WAILS-API.md` (sibling) — full binding signatures, push events, and model shapes.
- Wails v3 dialog signatures: `node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails v3 docs (may 403 from some clients): https://v3.wails.io/
- `../CLAUDE.md` for Go-side conventions, service registration, profile-switching policy, and Linux tray internals.
