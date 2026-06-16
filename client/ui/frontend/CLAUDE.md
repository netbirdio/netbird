# NetBird Wails UI — Frontend Working Notes

The React/TS frontend for the Wails v3 desktop UI. It runs inside the main Wails webview plus several auxiliary windows opened by Go (`services/windowmanager.go`). For Go-side conventions and the daemon gRPC layer see `../CLAUDE.md`.

> **Keep these notes current.** Update this file whenever you change conventions, rename a context/provider, change the route table, add/remove a top-level dependency, or introduce a cross-cutting feature (i18n, theming, etc.). A cold-start agent should be able to orient from these notes without re-deriving the codebase.

## Stack & tooling

React 18 + TS 5.7 (`strict`, `noImplicitAny: false`) + Vite 6 + Tailwind 3 (`darkMode: "class"`) + Radix primitives + i18next + `@wailsio/runtime`. React Router v7 `HashRouter` (Wails serves a static bundle). pnpm only — `package.json` is authoritative for deps and scripts. Class merging: `cn(...)` in `src/lib/cn.ts`. framer-motion is used only by the connect toggle. `task dev` from `client/ui/` is the canonical dev entry point — it runs Vite on `WAILS_VITE_PORT || 9245`.

## Path aliases & bindings

`@/*` → `src/*`, `@bindings/*` → `bindings/github.com/netbirdio/netbird/client/ui/*` (set in both `tsconfig.json` and `vite.config.ts`). Canonical imports: `from "@bindings/services"` (functions) and `from "@bindings/services/models.js"` (types).

`bindings/` is gitignored and fully generated. A fresh clone has no `bindings/` on disk, so `pnpm typecheck` fails until you run `pnpm bindings` (or `wails3 generate bindings -clean=true -ts` from `client/ui/`) once. `wails3 dev` regenerates on its own.

## Routing (`app.tsx`)

`HashRouter`. Dialog routes are grouped under a parent `<Route path="dialog">` (URL grouping only, no shared layout); the two in-window routes sit under `<AppLayout>`. The Go side mirrors the prefix — `WindowManager` opens windows at `/#/dialog/<name>`.

| Path | Component (module) | Layout | Window |
|---|---|---|---|
| `/` | `MainPage` (modules/main/) | `AppLayout` | Main window |
| `/settings` | `SettingsPage` (modules/settings/) | `AppLayout` | Settings auxiliary window |
| `/dialog/browser-login` | `LoginWaitingForBrowserDialog` (modules/login/) | none | SSO browser-wait, always-on-top |
| `/dialog/install-progress` | `UpdateInProgressDialog` (modules/auto-update/) | none | Install progress, always-on-top |
| `/dialog/session-expiration` | `SessionExpirationDialog` (modules/session/) | none | Session expiry warning, always-on-top |
| `/dialog/welcome` | `WelcomeDialog` (modules/welcome/) | none | First-launch onboarding |
| `/dialog/error` | `ErrorDialog` (modules/error/) | none | App's single error surface, always-on-top |
| `*` | `<Navigate to="/">` | `AppLayout` | Catch-all |

Auxiliary-window behaviour (sizing, always-on-top, create/destroy lifecycle) lives Go-side in `services/windowmanager.go` — see `../CLAUDE.md`. Frontend-relevant notes per window:

- **Settings** — opened via `WindowManager.OpenSettings(tab)`. The window stays at `/#/settings` for its whole lifetime (no `SetURL` between opens, so `AppLayout`'s providers never remount). Active tab is React local state in `SettingsPage`, set from the `netbird:settings:open` event Go emits before `Show`. Reset-to-General on close is driven in React by a `document.visibilitychange` listener (the Page Visibility API fires before WebKit throttles the hidden page, unlike a Go close-hook event which races `Hide` and flashes the previous tab for one frame).
- **install-progress** — owns the install-result polling + 5s daemon-down-grace, calls `Update.Quit()` on success. Opened by `ClientVersionContext.triggerUpdate` (user-driven enforced branch) and on the `installing` flip from `netbird:update:state` (force-install branch).
- **session-expiration** — `?seconds=` drives an mm:ss countdown; at zero it flips to the expired copy. Sign-in / Stay-connected emit `trigger-login`; Logout calls `Connection.Logout`.
- **welcome** — opened from Go's `ApplicationStarted` hook only when `prefStore.Get().OnboardingCompleted` is false. Two-step state machine: tray-screenshot pitch → Cloud-vs-self-hosted step (conditional, see `shouldShowManagementStep`). Continue calls `Preferences.SetOnboardingCompleted(true)`, then `WindowManager.OpenMain()`, then `WindowManager.CloseWelcome()`.
- **error** — `errorDialog({Title, Message})` in `lib/errors.ts` opens this (not a native OS box). `title` is the window chrome title (set Go-side, not in the body); `message` is read from `useSearchParams` and rendered next to a danger `SquareIcon`, with a Close button (Escape also closes → `WindowManager.CloseError()`).

## Layouts

`AppLayout` is the only router-level layout. It mounts the shared provider stack and renders `<Outlet/>`:

```
DialogProvider → StatusProvider → ProfileProvider → DebugBundleProvider → ClientVersionProvider
```

- `DialogProvider` is outermost (and outside the daemon gate) so `useConfirm()` works regardless of daemon state.
- `StatusProvider` owns the single `DaemonFeed.Get` + `netbird:status` subscription and **only renders its children when the daemon is reachable** — otherwise it short-circuits to `<DaemonUnavailableOverlay/>`. Consequence: every downstream context can assume the daemon is reachable at mount, so no per-context availability gating. When the daemon flips unavailable the whole subtree unmounts and remounts fresh on return.
- Order matters: `SettingsContext` (mounted in `SettingsPage`) depends on `ProfileContext`; `ClientVersionContext` reads `StatusContext` events.

`AppRightPanel` (in `layouts/`) is the shared content-panel shell used by the advanced-mode body; it supports an overlay slot (the peer-detail panel slides over it).

Page-specific chrome and providers live in the page, not the layout:

- **`MainPage`** (main window only) mounts `ViewModeProvider` (wraps the whole page — both `MainHeader` and `MainBody` read view mode; it calls `Window.SetSize`, so it must not be visible to the Settings window), `NetworksProvider`, and `PeerDetailProvider`. `NavSectionProvider` is mounted **only** inside the advanced-mode branch — default mode has no Peers/Networks tabs and no consumer of `useNavSection`.
- **`SettingsPage`** owns the `wails-draggable` strip at the top (so the macOS traffic-light buttons floating over the frameless window don't overlap content), then renders the vertical tabs.

## Directory layout (`src/`)

- `app.tsx` — root render + route table. The canonical registry of every route. Also wires init-time bootstrap (`initLogForwarding`, `welcome`, `initI18n`, `initPlatform`) before first render.
- `layouts/` — `AppLayout.tsx` (the only router-level layout) and `AppRightPanel.tsx` (shared content-panel shell).
- `modules/<feature>/` — each feature owns its folder: a `*Page.tsx` entry where applicable, plus its local components.
  - `main/` — `MainPage.tsx`, `MainHeader.tsx`, `MainConnectionStatusSwitch.tsx` (connect toggle + the `startLogin` SSO orchestrator), `MainExitNodeSwitcher.tsx`.
    - `main/advanced/` — advanced-mode-only surfaces: `Navigation.tsx` (Peers/Networks tab switch) plus `peers/` (`Peers.tsx`, `PeerDetailPanel.tsx`, `PeerFilters.tsx`) and `networks/` (`Networks.tsx`, `NetworkFilters.tsx`). There is no exit-nodes sub-module — exit-node state lives in `NetworksContext` and the UI is `MainExitNodeSwitcher` (shown in default mode too).
  - `settings/` — `SettingsPage.tsx`, `SettingsNavigation.tsx`, `SettingsSection.tsx`, `SettingsSkeleton.tsx`, and the tab files flat (`SettingsGeneral`, `SettingsNetwork`, `SettingsSecurity`, `SettingsSSH`, `SettingsAdvanced`, `SettingsTroubleshooting`, `SettingsAbout`, `SettingsAccent`). The Profiles tab is `modules/profiles/ProfilesTab.tsx`.
  - `profiles/` — `ProfileDropdown.tsx` (header), `ProfileCreationModal.tsx`, `ProfilesTab.tsx` (settings table), `ProfileAvatar.tsx`. Context in `contexts/ProfileContext.tsx`. The creation modal collects a profile name + management target (Cloud vs self-hosted + URL, reusing `ManagementServerSwitch` + `useManagementUrl`); `ProfilesTab.handleCreate` adds the profile, `Settings.SetConfig`s the `managementUrl` onto it (keyed by profile name, before switching), then switches. Row actions confirm via `useConfirm()`.
  - `welcome/` — `WelcomeDialog.tsx` (orchestrator) + `WelcomeStepTray.tsx`, `WelcomeStepManagement.tsx`. The management step renders only when active profile is `"default"`, the profile email is empty, and the management URL is cloud-default-or-empty (`shouldShowManagementStep`). Self-hosted URL reachability is a soft warning (`useManagementUrl.checkManagementUrlReachable`) — the user can re-click Continue to proceed past a failed check.
  - `login/` — `LoginWaitingForBrowserDialog.tsx` (SSO browser-wait window).
  - `session/` — `SessionExpirationDialog.tsx`.
  - `auto-update/` — `UpdateInProgressDialog.tsx`, `UpdateBadge.tsx`, `UpdateVersionCard.tsx`. Context in `contexts/ClientVersionContext.tsx`.
  - `error/` — `ErrorDialog.tsx`.
- `contexts/` — every React context as a flat file: `StatusContext`, `ProfileContext`, `DebugBundleContext`, `ClientVersionContext`, `SettingsContext`, `MdmContext`, `NetworksContext`, `PeerDetailContext`, `ViewModeContext`, `NavSectionContext`, `DialogContext`. Mental model: "where is the X context? `contexts/XContext.tsx`."
- `components/` — presentational primitives, no daemon RPCs, no router:
  - `buttons/` — `Button`, `IconButton`.
  - `inputs/` — `Input`, `SearchInput`.
  - `dialog/` — `Dialog`, `DialogActions`, `DialogDescription`, `DialogHeading`, `ConfirmDialog` (window-based dialog layout primitive), `ConfirmModal` (in-app Radix confirmation, usually driven via `useConfirm()`).
  - `switches/` — `SwitchItem`, `SwitchItemGroup`, `ToggleSwitch`, `FancyToggleSwitch`.
  - `typography/` — `Label`, `HelpText`.
  - `empty-state/` — `EmptyState`, `NoResults`, `NotConnectedState`, `DaemonUnavailableOverlay`.
  - Flat at root: `Badge`, `CopyToClipboard`, `DropdownMenu`, `SquareIcon`, `Tooltip`, `TruncatedText`, `VerticalTabs`, `LanguagePicker`, `ManagementServerSwitch`.
- `hooks/` — `useAutoSizeWindow.ts` (auto-size + `Window.Show` for auxiliary dialogs), `useKeyboardShortcut.ts`, `useManagementUrl.ts` (management-URL helpers: `CLOUD_MANAGEMENT_URL`, `isValidManagementUrl`, `normalizeManagementUrl`, `isNetbirdCloud`, `checkManagementUrlReachable`).
- `lib/` — pure utilities (no JSX, no React state): `cn.ts`, `errors.ts` (`formatErrorMessage` + the `errorDialog({Title, Message})` window wrapper), `formatters.ts` (byte/latency/relative-time + `shortenDns`), `sorting.ts` (`reconcileOrder` — order-preserving list reconciliation shared by the peers/networks/profiles lists), `i18n.ts`, `logs.ts` (forwards console + uncaught errors to the Go log pipeline), `platform.ts` (`isMacOS`/`isWindows`), `welcome.ts`.
- `assets/` — fonts, logos, flags.

## Wails event bus

Subscribe with `Events.On(name, handler)`; the handler receives `{ data: <typed payload> }`. Event-name strings live next to their usage (no central TS registry). Prefer one subscription at the context level over per-screen — the bus is process-wide and each `Events.On` adds an emit-time fan-out.

| Event name | Payload | Emitted by | Consumed by |
|---|---|---|---|
| `netbird:status` | `Status` | `services/peers.go` | `StatusContext` (the only subscriber) |
| `netbird:profile:changed` | `ProfileRef` | `services/profileswitcher.go SwitchActive` | `ProfileContext` — refreshes so a tray-initiated switch paints in the UI |
| `netbird:update:state` | `UpdateState` | `services/peers.go fanOutUpdateEvents` + the updater's `progress_window:show` translator | `ClientVersionContext` — single source of truth for `updateAvailable / version / enforced / installing` |
| `netbird:settings:open` | `string` (tab id) | `services/windowmanager.go OpenSettings` (before `Show`) | `SettingsPage` — `setActive(e.data)`. Reset-on-close is the `visibilitychange` listener, not this event. |
| `netbird:preferences:changed` | `{ language }` | Go after `SetLanguage` / `SetViewMode` | `lib/i18n.ts` — calls `i18next.changeLanguage` so a flip from any window paints everywhere |
| `browser-login:cancel` | (none) | `LoginWaitingForBrowserDialog` Cancel button **or** Go on window close | `MainConnectionStatusSwitch`'s `startLogin()` to abort the in-flight `WaitSSOLogin` |
| `trigger-login` | (none) | `services.EventTriggerLogin` (reserved; no Go emitter today) | `MainConnectionStatusSwitch` subscribes and runs `startLogin()` |

`netbird:event`, `netbird:update:available`, and `netbird:update:progress` are emitted Go-side for the tray but **not** subscribed on the TS side — the UI derives the same info from `useStatus().status.events`.

## Contexts and state

State that crosses screens/windows lives in context, each provider mounted exactly once.

- **`useStatus`** (`StatusContext`) — `{ status, error, refresh, isReady, isDaemonAvailable, isDaemonUnavailable }`. Owns the single `DaemonFeed.Get` + `netbird:status` subscription and the daemon gate (see Layouts). `refresh()` after Connect/Disconnect to dodge a few hundred ms of event-stream lag.
- **`ProfileContext`** — `username`, `activeProfile`, `profiles`, plus `refresh` / `switchProfile` / `addProfile` / `removeProfile` / `logoutProfile`. `switchProfile` delegates to `ProfileSwitcher.SwitchActive` (the Go-side single source of truth — drives the optimistic-Connecting paint and `Peers` suppression). The other methods are thin wrappers over `Profiles.*` / `Connection.Logout` + a `refresh()`.
- **`SettingsContext`** — `setField` / `saveField` / `saveFields` / `saveNow` over `Settings.GetConfig|SetConfig` with 400ms debounce. Renders `<SettingsSkeleton/>` while `config === null`. **PSK mask quirk:** `GetConfig` returns existing PSKs as `"**********"`; sending the mask back round-trips it into storage and `wgtypes.ParseKey` fails on the next connect — `save` drops the field when it equals the mask.
- **`MdmContext`** — `useMdm()` returns `config.managedFields` as `Record<string, boolean>`, **keyed by the daemon's `mdm.Key*` names exactly as written in the policy source** (`managementURL`, `allowServerSSH`, `preSharedKey`, `wireguardPort`, `rosenpassEnabled`/`Permissive`, `disableClientRoutes`/`disableServerRoutes`, `disableAutoConnect`, `blockInbound`). No GUI-side renaming — what the Group Policy admin writes is what the lookup key is. Mounted in `AppLayout` (under `ProfileProvider`); fetches `Settings.GetConfig` once, re-fetches on the daemon's `netbird:event` `metadata.type=config_changed` push so policy flips paint live. No second copy of the locked *values* — MDM is a global override, so the active profile's resolved `useSettings().config.<field>` already carries the MDM-enforced value. Consumers: Settings tabs hide individual toggles/sections (both rosenpass keys managed ⇒ whole encryption section hidden); `mdm.*` fields are **is-managed flags** — `true` when the field name appears in `MDMManagedFields`, `false` otherwise. Consumers check truthiness (`!mdm.x` to mean "not managed"). The *resolved value* of a managed field is already enforced into `Config`, so consumers read it via `useSettings().config.<field>` and hide the toggle when `mdm.<field>` is true. **Three carve-outs** that carry the resolved value instead, populated outside the reflective is-managed loop in `services/settings.go` `GetRestrictions`: `mdm.managementURL` (string — used by `ProfileCreationModal` / `WelcomeDialog`, which need the URL to render the form); `mdm.allowServerSSH` (`*bool` / `boolean | null` — used by `SettingsNavigation` + `SettingsPage` to gate the SSH tab on `mdm.allowServerSSH ?? !features.disableUpdateSettings`; tri-state needed because the tab gate lives outside `SettingsProvider` and can't read `config.serverSshAllowed`, and MDM-managed-with-value-`false` must hide the tab — falsy fallthrough would leak it); and `mdm.disableAdvancedView` (`bool` — MDM-only on the daemon, no CLI fallback; plumbed via the `GetFeatures` RPC rather than `MDMManagedFields`, so set directly from `featResp.GetDisableAdvancedView()`. Value semantic: `true` iff MDM explicitly disables; the nil/false collapse is fine because both mean "advanced view available"). The three `features.*` gates (`disableProfiles`/`Networks`/`UpdateSettings`) live in `Features` because they accept a CLI-flag fallback in addition to MDM (`--disable-profiles` etc.) — `disableAdvancedView` doesn't, which is why it sits with the MDM-only carve-outs. `ProfileCreationModal` skips the Cloud/self-hosted picker when `managed.managementURL` is set and submits the resolved URL verbatim; `WelcomeDialog` reads `config.managedFields.managementURL` directly (sits outside `AppLayout`) to skip the management step on a fresh install.
- **`DebugBundleContext`** — stages `idle → preparing-trace → reconnecting → capturing → restoring-level → bundling → uploading → done`. Cancellable via `AbortController` at any stage; cancel restores the original log level best-effort. Upload URL is the hardcoded `NETBIRD_UPLOAD_URL`.
- **`ClientVersionContext`** — seeds from `Update.GetState()`, subscribes to `netbird:update:state`; exposes `{ updateAvailable, updateVersion, enforced, installing, triggerUpdate, updating }`. Three branches:
  1. `available && !enforced` — download-only; `UpdateVersionCard` → opens GitHub releases.
  2. `available && enforced && !installing` — user-driven; `triggerUpdate` opens the install-progress window then calls `Update.Trigger()`.
  3. `available && enforced && installing` — daemon already installing; the flip auto-opens the install-progress window.
- **`NetworksContext`** — routed networks + exit nodes derived from `status.networks`; optimistic overrides for instant toggle feedback. **`PeerDetailContext`** — which peer detail panel is open in advanced view. **`NavSectionContext`** — the advanced-mode Peers/Networks tab selection.

### View mode + no client-side persistence

`ViewModeProvider` (`contexts/ViewModeContext.tsx`, mounted in `MainPage`) owns `viewMode: "default" | "advanced"`, consumed via `useViewMode()`. `setViewMode` updates state, calls `Window.SetSize(width, <live frame height>)`, and persists via `Preferences.SetViewMode`. Widths live in `VIEW_WIDTH`: Default 380, Advanced 900. **The height is intentionally not asserted** — we read the current frame height via `Window.Size()` and pass it back, because Wails' macOS `windowSetSize` is `setFrame:` (frame, incl. ~28px title bar) while initial `windowNew` uses `initWithContentRect:` (content). Passing a constant would chop ~28px off the content area on the first switch. `main.go` opens the window at the saved width so there's no 380→900 flash on launch; the provider hydrates from `Preferences.Get()` on mount without triggering a resize.

**No `localStorage` / `sessionStorage` / cookies anywhere** — persistence is the Go side's job: settings → `SetConfig`, language → `Preferences.SetLanguage`, view mode → `Preferences.SetViewMode`.

## Localisation (i18n)

Bootstrap in `src/lib/i18n.ts`, awaited before render in `app.tsx`. It reads the current language from `Preferences.Get()`, glob-imports every bundle from the shared tree at `client/ui/i18n/locales/` (sibling of the Go i18n package — same JSON drives both tray and React), inits i18next with `fallbackLng: "en"` and `interpolation: { prefix: "{", suffix: "}" }`, and subscribes to `netbird:preferences:changed` so a flip from any window calls `i18next.changeLanguage` here.

**First-run browser-language detection.** When no preferences file exists, `Preferences.Get()` returns `language: ""` (the Go "unset" signal). `initI18n` walks `navigator.language` + `navigator.languages`, lowercases each, and picks the first base code (`de` from `de-DE`) with a shipped bundle — then `Preferences.SetLanguage(detected)` fire-and-forget so the next launch reads it back. No match (or store unreachable) falls through to `en`. From the second launch the persisted value wins.

**Usage.** Default to the hook:

```ts
import { useTranslation } from "react-i18next";
const { t } = useTranslation();
t("settings.tabs.general");
t("update.card.versionAvailable", { version: updateVersion }); // placeholders
```

Outside React (module-scope event handlers, error titles) import the instance directly: `import i18next from "@/lib/i18n"`.

**Bundle files.** Keys live in `client/ui/i18n/locales/<code>/common.json` in Chrome-extension JSON shape: each key maps to `{ "message": "...", "description": "..." }`. `description` is translator context for Crowdin (read from the source file, ignored at runtime) — only `en/common.json` carries descriptions; target bundles carry just `message`. `lib/i18n.ts` strips each entry to its `message` when building the i18next `resources`, so `t()` lookups are unchanged. Placeholders use single braces: `"Install version {version}"`. Add a key to `en/common.json` first (the fallback), then to every other locale. Missing keys fall back to English, then to the key itself (so the gap is visible in the UI).

**Translating bundles.** `client/ui/i18n/TRANSLATING.md` is the authoritative brief for actually producing or reviewing a translation — written for any translator (human or AI agent). It carries the product context, the file-format rules, the placeholder/`\n`/plural constraints (the app has only a one/other plural split — no ICU rules), the per-language do-vs-don't-translate glossary (e.g. "Exit Node" stays English in de/hu but is translated in ru/es/fr/it/pt/zh), and the new-language + review procedures. Read it before adding or editing any locale; keep its glossary/procedures current when conventions change.

**Adding a language.** Drop `client/ui/i18n/locales/<code>/common.json` (follow `TRANSLATING.md`) and append the row to `_index.json`. No flag asset is needed — `LanguagePicker.tsx` deliberately ships no flags ("flags represent countries, not languages"). `lib/i18n.ts` discovers bundles via `import.meta.glob('../../../i18n/locales/*/common.json', { eager: true })` (the tree lives outside `frontend/`, so `vite.config.ts` whitelists the parent dir under `server.fs.allow`) — no code change needed to wire a new locale.

**What gets translated.** Every user-facing string. Don't add hard-coded English — add the key, then `t()`. Internal log strings and the `Update failed` fallback fed into `classifyError()` are not translated.

## Login flow (`startLogin` in `MainConnectionStatusSwitch.tsx`)

The SSO flow is a module-level `startLogin()` with a `loginInFlight` guard so a double-click can't fire two concurrent flows. Sequence:

1. `Connection.Login({})` with empty fields — Go fills in active profile + OS user.
2. If SSO is needed (`needsSsoLogin`):
   - `WindowManager.OpenBrowserLogin(uri)` opens the sign-in popup (hidden until React mounts and `useAutoSizeWindow` calls `Window.Show`).
   - The dialog fires `Connection.OpenURL(uri)` from its mount effect (done from the dialog, not `startLogin`, so the browser doesn't race the still-hidden popup).
   - `Promise.race(WaitSSOLogin, browser-login:cancel)`.
   - On cancel: cancel the in-flight `WaitSSOLogin` gRPC so the daemon drops the abandoned device code.
3. `Connection.Up({})` to bring the new session up.

`onSettled` (releasing the caller's React-level guard) fires the instant the flow ends — **before** the error dialog — never gated on the dialog. Errors that aren't cancellations surface via `errorDialog`. This is the only SSO entry point; there's no `/login` route — wire any new SSO trigger through here.

## Dialogs convention

**Errors → `errorDialog({Title, Message})` from `src/lib/errors.ts`** (which also exports `formatErrorMessage`), never `Dialogs.*` from `@wailsio/runtime`. Despite the name it opens the custom always-on-top `/#/dialog/error` window via `WindowManager.OpenError` (`modules/error/ErrorDialog.tsx`), not a native OS box. Use an action-named title ("Save Settings Failed", not "Error"). Title/message must already be localised. **`errorDialog()` resolves as soon as the window opens — it does not block until dismissed.**

For **confirmations**, use `useConfirm()` from `contexts/DialogContext.tsx` — `const ok = await confirm({ title, description, confirmLabel, danger? })` resolves to a boolean. It renders a single shared `ConfirmModal` mounted at the provider level. Used by the Profiles tab and the management-server cloud switch.

**Skip dialogs entirely** for inline form validation, transient link errors on the dashboard, and "partial success" notes inside an otherwise-OK flow. Full rationale in `../CLAUDE.md`.

## Tailwind tokens

Defined in `tailwind.config.ts`. `nb-gray` is the neutral palette (background `nb-gray-950`); `netbird` is brand orange (`#f68330`). New code uses `nb-gray` + `netbird` + semantic dot colors (`green-500`, `red-500`, `yellow-500`). `bg-conic-netbird` and the `pulse-reverse` / `spin-slow` / `ping-slow` keyframes are used only by the connect toggle. Fonts: Inter Variable (sans) + JetBrains Mono Variable (mono), under `src/assets/fonts/`.

## Wails-specific quirks

- **Window dragging.** Class `wails-draggable` on regions that should drag the OS window (headers, the Settings title strip, dialog wrappers). `wails-no-draggable` on interactive children inside a draggable region (buttons, inputs) — otherwise the drag swallows their click.
- **Webview asset access.** Reference assets through Vite: `import url from "@/assets/.../foo.svg"`. Absolute filesystem paths don't work in dev or prod.
- **`Window.SetSize(w, h)`.** Called from `ViewModeContext`'s `setViewMode`. Height is read fresh from `Window.Size()` and re-passed — see the View mode section for why a constant would shrink the content area.
- **Main-window width.** Windows uses a slightly narrower content width than macOS to compensate for the OS frame Wails counts differently (`MainPage` → `isWindows() ? 364 : 380`; see wails/wails#3260).
- **`Browser.OpenURL(url)`.** Used by `SettingsAbout` (legal links) and the BrowserLogin "Try again". `SettingsAbout` has a `window.open` fallback for when Wails refuses (non-http schemes are rejected).

## Useful references

- `WAILS-API.md` (sibling) — full per-service binding signatures, push-event payloads, and model field shapes. Every method returns `$CancellablePromise<T>` (`await` and ignore `.cancel()` in practice). Regenerate via `pnpm bindings` after any Go-side change.
- Wails v3 dialog signatures: `node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails v3 docs (may 403 from some clients): https://v3.wails.io/
- `../CLAUDE.md` — Go-side conventions, service registration, profile-switching policy, auxiliary-window lifecycle, Linux tray internals.
