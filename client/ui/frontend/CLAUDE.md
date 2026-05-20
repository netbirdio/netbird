# NetBird Wails UI — Frontend Working Notes

This is the React/TS frontend for the Wails v3 desktop UI. It runs inside the main Wails webview plus two auxiliary windows (`/#/settings` and `/#/browser-login`) opened by Go (`services/windowmanager.go`). For Go-side conventions and the daemon gRPC layer see `../CLAUDE.md`.

> **Keep these notes current.** When working in this directory with Claude, update this file whenever you change conventions, rename a context/provider, shift the route table, add or remove a top-level dependency, or introduce a new cross-cutting feature (i18n, theming, telemetry, etc.). The aim is that a cold-start agent can orient itself from these notes without re-deriving the codebase.

> **Work in progress.** Big chunks of the UI are still mocked, prototyped, or duplicated across screens that pre-date the current AppLayout. Anything marked "prototype" / "mocked" / "legacy" below should be assumed half-wired. The polished surface today is: the main connect toggle, the Settings window, the debug-bundle flow, the auto-update overlay, and the profile selector. Everything else is in flight.

## Stack & tooling

React 18 + TS 5.7 (`strict`, `noImplicitAny: false`) + Vite 6 + Tailwind 3 (`darkMode: "class"`) + Radix primitives + i18next + `@wailsio/runtime`. React Router v7 `HashRouter` (Wails serves a static bundle). pnpm only — `package.json` is authoritative for deps and scripts. Class merging: `cn(...)` in `src/lib/cn.ts`. framer-motion is used only by `NetBirdConnectToggle`. `task dev` from `client/ui/` is the canonical dev entry point — it runs Vite on `WAILS_VITE_PORT || 9245`.

## Path aliases & bindings

`@/*` → `src/*`, `@bindings/*` → `bindings/github.com/netbirdio/netbird/client/ui/*` (set in both `tsconfig.json` and `vite.config.ts`). Canonical imports: `from "@bindings/services"` (functions) and `from "@bindings/services/models.js"` (types). A few legacy screens (`screens/Profiles.tsx`, `pages/Update.tsx`) still use deep `../../bindings/...` paths — treat as a smell.

`bindings/` is gitignored and fully generated. A fresh clone has no `bindings/` on disk, so `pnpm typecheck` fails until you run `pnpm bindings` (or `wails3 generate bindings -clean=true -ts` from `client/ui/`) once. `wails3 dev` regenerates on its own.

## Routing (app.tsx)

`HashRouter` with the following routes:

| Path | Component | Layout | Where it opens |
|---|---|---|---|
| `/` | `Main` | `AppLayout` | Main window default route |
| `/quick` | `QuickActions` | none | Standalone — **prototype**, not currently invoked by the Go side |
| `/browser-login` | `WaitingForBrowserDialog` (modules/authentication) | none | Auxiliary window (Go `WindowManager.OpenBrowserLogin`) |
| `/update` | `Update` (pages) | none | Main window during enforced-update install |
| `/session-expired` | `SessionExpiredDialog` (modules/authentication) | none | Auxiliary window (Go `WindowManager.OpenSessionExpired`, always-on-top) |
| `/session-about-to-expire` | `SessionAboutToExpireDialog` (modules/authentication) | none | Auxiliary window (Go `WindowManager.OpenSessionAboutToExpire(seconds)`, always-on-top, mm:ss countdown via `?seconds=`) |
| `/settings` | `Settings` | `SettingsLayout` | Auxiliary window (Go `WindowManager.OpenSettings(tab)`). The `Profiles` tab (`modules/settings/SettingsProfiles.tsx`, `UserCircle` icon, between Security and SSH) lists profiles in a table with Deregister/Delete in a per-row kebab and an Add Profile button. The header `ProfileDropdown`'s "Manage Profiles" entry calls `OpenSettings("profiles")` — `Settings.tsx` reads `?tab=` via `useSearchParams` so the window opens at that tab. |
| `*` | `<Navigate to="/">` | `AppLayout` | Catch-all |

`AppLayout` wraps `Header + <Outlet/>` in this provider order: `StatusProvider → ProfileProvider → DebugBundleProvider → ClientVersionProvider`. `StatusProvider` (in `modules/daemon-status/StatusContext.tsx`) owns the single `Peers.Get` + `netbird:status` subscription, exposes `{ status, error, refresh, isReady, isDaemonAvailable, isDaemonUnavailable }`, **and only renders its children when the daemon is reachable** — until the first `Peers.Get` resolves and on `DaemonUnavailable` it short-circuits to just the `<DaemonUnavailableOverlay/>` (also owned by the provider). The consequence: every context downstream (`ProfileProvider`, `DebugBundleProvider`, `ClientVersionProvider`) can assume the daemon is reachable at mount time — no per-context `useStatus` gating. When the daemon flips back to unavailable the whole downstream subtree unmounts and remounts fresh once it returns. The remaining order is structural — `DebugBundleProvider` reads `useProfile`, and `ClientVersionProvider` paints `<UpdatingOverlay/>` so it has to be outermost in z-index but innermost in the tree. `AppLayout` also owns the wide/narrow `expanded` state as plain `useState` (no persistence) and passes it to `Header` via props and to `Main` via Outlet context (`MainOutletContext`).

`SettingsLayout` uses the same provider stack minus the `Header`. It also reserves a 38px `wails-draggable` strip at the top so the macOS traffic-light buttons (the window uses `MacTitleBarHiddenInset`) don't overlap content.

## Directory layout (src/)

The split between `pages/`, `screens/`, and `modules/` is historical and not load-bearing. **Today:** `modules/` owns the polished AppLayout-shell-driven UI, `pages/` owns the few routes that live outside that shell, and `screens/` is the unsorted legacy bucket. Don't add new code under `screens/` — pick `pages/` (own route, no shell) or `modules/<feature>/` (lives inside the shell). `lib/MainModuleContext.tsx` is exported but unused — candidate for deletion.

## Wails event bus

Subscribe with `Events.On(name, handler)`. The handler receives `{ data: <typed payload> }`. The event name strings live next to their usage (no central registry on the TS side).

| Event name (string) | Payload | Emitted by | Consumed by |
|---|---|---|---|
| `netbird:status` | `Status` | `services/peers.go statusStreamLoop` | `modules/daemon-status/StatusContext` (`useStatus`) |
| `netbird:event` | `SystemEvent` | `services/peers.go toastStreamLoop` | Not currently subscribed on the TS side — Status is read via `useStatus().status.events` instead. The tray (Go) consumes it for OS notifications. |
| `netbird:profile:changed` | `ProfileRef` | `services/profileswitcher.go SwitchActive` | `modules/profile/ProfileContext` refreshes so a tray-initiated switch paints in the React UI. |
| `netbird:update:available` | `UpdateAvailable` | `services/peers.go fanOutUpdateEvents` | Not directly subscribed on the TS side; `ClientVersionContext` derives `updateVersion` from `status.events` metadata instead. |
| `netbird:update:progress` | `UpdateProgress` | same | Same — drives the tray; Go side opens the `/update` route. |
| `browser-login:cancel` | (no payload) | `BrowserLogin` page (frontend) when user clicks Cancel **or** Go `services/windowmanager.go` when user closes the BrowserLogin window | `layouts/ConnectionStatusSwitch.tsx`'s `startLogin()` to abort the in-flight `WaitSSOLogin` |
| `trigger-login` | (no payload) | Reserved (`services.EventTriggerLogin`); `layouts/ConnectionStatusSwitch.tsx` subscribes and runs `startLogin()` when fired. No Go-side emitter today. |

If you wire a new daemon-event subscriber on the TS side, prefer subscribing once at the context level rather than per-screen — the Wails event bus is process-wide and each `Events.On` adds an emit-time fan-out.

## Contexts and state

State that crosses screens / windows lives in context. Each provider is mounted exactly once inside `AppLayout` or `SettingsLayout`.

- **`useStatus`** (`modules/daemon-status/StatusContext.tsx`) — `{ status, error, refresh, isReady, isDaemonAvailable, isDaemonUnavailable }`. The provider owns a single `Peers.Get()` + `netbird:status` subscription and renders `<DaemonUnavailableOverlay/>`. `refresh()` after Connect/Disconnect to dodge a few hundred ms of event-stream lag. Other contexts (e.g. `ProfileContext`) read the boolean flags to skip RPCs while the daemon socket is down.

- **`ProfileContext`** (`modules/profile/`) — `username`, `activeProfile`, `profiles`, plus `refresh` / `switchProfile` / `addProfile` / `removeProfile` / `logoutProfile`. `switchProfile` delegates to `ProfileSwitcher.SwitchActive` (the Go-side single source of truth — drives the optimistic-Connecting paint and `Peers` suppression). The other methods are thin wrappers over `Profiles.*` / `Connection.Logout` plus a `refresh()`.

- **`SettingsContext`** (`modules/settings/`) — `setField` / `saveField` / `saveFields` / `saveNow` over `SettingsSvc.GetConfig|SetConfig` with 400ms debounce. Renders `<SkeletonSettings/>` while `config === null` so tabs never see null. **PSK mask quirk:** `GetConfig` returns existing PSKs as `"**********"`; sending the mask back round-trips it into storage and `wgtypes.ParseKey` fails on the next connect. `save` drops the field when it equals `"**********"`.

- **`DebugBundleProvider` + `useDebugBundle`** (`modules/debug-bundle/`) — stages: `idle → preparing-trace → reconnecting → capturing → restoring-level → bundling → uploading → done`. Cancellable via `AbortController` at any stage; cancel restores the original log level best-effort. Wrapped in a context so the troubleshooting tab keeps stage across navigation. Upload URL is the hardcoded `NETBIRD_UPLOAD_URL`.

- **`ClientVersionContext`** (`modules/auto-update/`) — derives `updateAvailable` / `updateVersion` from `Status.events` metadata (`new_version_available` key), exposes `triggerUpdate`, mounts `<UpdateAvailableBanner/>` + `<UpdatingOverlay/>` so every screen inherits them. **Dev preview flags at the top of the file** (`FORCE_UPDATE_AVAILABLE`, `FORCE_UPDATING`, `FORCE_VERSION`, `HIDE_UPDATE_AVAILABLE`, `FORCE_ERROR`, `FORCE_ERROR_MSG`) override daemon state for UI preview. `FORCE_UPDATE_AVAILABLE = true` is currently committed — flip back to `false` before a real release. `UpdateAvailableBanner` additionally returns null in `import.meta.env.DEV`.

### Wide/narrow panel + no client-side persistence

The `expanded` flag (380px ↔ 925px) lives in `AppLayout` as plain `useState(false)` — the only shell-layout knob. `Header.tsx` reads it via props and calls `Window.SetSize(w, 615)`; `Main.tsx` reads it via `MainOutletContext` to mount/unmount the right-side panel. Every app launch starts small. **No `localStorage` / `sessionStorage` / cookies anywhere in the frontend** — persistence is the Go side's job (settings → `SetConfig`, language → `Preferences.SetLanguage`). Nav-item visibility and header buttons are hardcoded to always-render (the old Appearance toggles are gone).

## Localisation (i18n)

Bootstrap lives in `src/i18n/index.ts` and is awaited before render in `app.tsx`. It reads the current language from `Preferences.Get()`, statically imports every bundle JSON (`en/common.json`, `de/common.json`, `hu/common.json` today), initialises i18next with `fallbackLng: "en"` and `interpolation: { prefix: "{", suffix: "}" }`, and subscribes to the `netbird:preferences:changed` Wails event so a flip from any window (tray, settings, another renderer) calls `i18next.changeLanguage` here.

**No first-run detection.** When no preferences file exists, `Preferences.Get()` returns `{language: "en"}` from the Go-side in-memory default. The frontend treats `en` as the fallback (i18next `fallbackLng: "en"`) and users pick a different language via the picker in `SettingsGeneral`. The Go store persists on the first explicit `SetLanguage`.

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

**Bundle files.** Keys live in `src/i18n/locales/<code>/common.json` as a flat key→string map (`"settings.tabs.general": "General"`). Placeholders use single braces: `"Install version {version}"`. Adding a key: add to `en/common.json` first (the fallback), then every other locale. Missing keys fall back to English; if even that misses, i18next returns the key itself so the gap is visible in the UI rather than blank.

**Adding a language.** Drop `src/i18n/locales/<code>/common.json` and append the row to `src/i18n/locales/_index.json`. That's it — `src/i18n/index.ts` discovers bundles via `import.meta.glob('./locales/*/common.json', { eager: true })`, so no code change is needed to wire the new locale in. Vite still inlines each bundle at build time, same chunk shape as static imports. The Go side reads the same tree (embedded via `client/ui/main.go`'s `embed.FS`), so the tray menu localises automatically off the same files.

**Language picker.** `src/modules/settings/LanguagePicker.tsx` is mounted inside the Language section of `SettingsGeneral.tsx`. It populates from `I18n.Languages()` (matches `_index.json`) and calls `Preferences.SetLanguage(code)` on selection. The preference write triggers `netbird:preferences:changed`, which both the local i18next instance and every other open window listen to.

**What gets translated.** Every user-facing string in the polished AppLayout/Settings/Update/BrowserLogin/SessionExpired/Peers surfaces. Don't add hard-coded user-facing English to new code — add the key, then `t()`. Internal log strings, dev-only forced-state strings in `ClientVersionContext`, and the `Update failed` fallback fed into `classifyError()` (which then renders a translated description) are not translated.

## Login flow (`startLogin` in `ConnectionStatusSwitch.tsx`)

The SSO flow is centralised in a module-level `startLogin()` with a `loginInFlight` guard so a double-click can't fire two concurrent flows. Sequence:

1. `Connection.Login({})` with empty fields — Go fills in active profile + OS user.
2. If the daemon needs SSO (`needsSsoLogin`):
   - `Connection.OpenURL(uri)` opens the verification page in the system browser (honors `$BROWSER`).
   - `WindowManager.OpenBrowserLogin(uri)` opens the auxiliary "waiting for sign-in" window.
   - `Promise.race(WaitSSOLogin, EVENT_BROWSER_LOGIN_CANCEL)` — whichever resolves first.
   - On cancel: `Connection.Down()` to dislodge the daemon's pending `WaitSSOLogin` so the next Login starts fresh (see `services/connection.go:74`).
3. `Connection.Up({})` to bring the new session up.

Errors that aren't cancellations surface via `Dialogs.Error`.

This is the only SSO entry point used by the polished Main UI. Legacy screens (`screens/Status.tsx`, `screens/Profiles.tsx`) link to a `/login` route that **does not exist** in `app.tsx` today — those navigations will fall through the `*` catch-all to `/`. Those screens are not part of the live route table, so it doesn't bite users, but don't add a new `useNavigate("/login")` without first wiring an actual route.

## Components

`src/components/` holds presentational primitives (no daemon RPCs, no router) — see the directory listing. Settings rows use `FancyToggleSwitch` inside `<SectionGroup title=…>` (section-group dimming via `disabled` → greyed + `pointer-events-none`). In-app modals use the Radix `Dialog` primitive in the main webview; the two auxiliary OS windows (Settings, BrowserLogin) are created Go-side via `WindowManager`.

## Dialogs convention

Errors → `Dialogs.Error` with action-named title ("Save Settings Failed", not "Error"). Confirmations → `Dialogs.Warning` with explicit `Buttons` — compare against the **Label string**, not an index. **Skip** native dialogs for inline form validation, transient link errors on the dashboard, and "partial success" notes inside an otherwise-OK flow. Full API + per-OS notes in `../WAILS-DIALOGS.md`; full convention rationale in `../CLAUDE.md`.

## Tailwind tokens

Defined in `tailwind.config.ts`. `nb-gray` is the neutral palette (background = `nb-gray-950`); `netbird` is brand orange (`#f68330`). The Flowbite-style `gray`/`red`/`yellow`/`...` palettes are legacy — only use them inside `screens/*`; new code sticks to `nb-gray` + `netbird` + semantic dot colors (`green-500`, `red-500`, `yellow-500`). `bg-conic-netbird` and the `pulse-reverse` / `spin-slow` / `ping-slow` keyframes are used only by `NetBirdConnectToggle`. Fonts: Inter Variable (sans) + JetBrains Mono Variable (mono), shipped under `src/assets/fonts/`.

## Wails-specific quirks

- **Window dragging.** Use class `wails-draggable` on regions that should drag the OS window (the Header, the SettingsLayout title strip, the UpdatingOverlay). Use `wails-no-draggable` on interactive children inside a draggable region (buttons, inputs) — otherwise the drag swallows their click.
- **Webview asset access.** Background images / fonts go through Vite at build time, so reference them with `import url from "@/assets/.../foo.svg"`. The Wails dev server proxies `/` to Vite, but absolute filesystem paths won't work in either dev or prod.
- **`Window.SetSize(w, h)`.** Called from `Header.tsx` to switch between 380-wide and 925-wide layouts. There's a one-time initial sync on mount so localStorage's `expanded` flag wins over the Go-side default of 925.
- **`Browser.OpenURL(url)`.** Used by `SettingsAbout` for legal links and by the `BrowserLogin` page's "Try again". Has a `window.open` fallback in `SettingsAbout` for the case where Wails refuses (non-http schemes are rejected by Wails).

## Things in flight (don't be surprised by)

- **`screens/Peers.tsx`** uses live `Peers.Get` data. **`modules/peers/Peers.tsx`** uses `mockPeers.ts`. The mock-driven one is mounted under `Main.tsx`'s `MainRightSide` and is what the user sees today; the real-data one isn't wired into the route table.
- **`screens/Profiles.tsx`** still imports bindings via the deep relative path. It's the example of the preferred `ProfileSwitcher.SwitchActive` flow but otherwise pre-AppLayout.
- **`pages/Debug.tsx`** is the legacy debug-bundle screen. The polished flow is in `modules/settings/SettingsTroubleshooting.tsx` (via `useDebugBundle`). `pages/Debug.tsx` isn't currently routed.
- **`pages/Update.tsx`** and **`screens/Update.tsx`** are two different update pages. The route table points at `pages/Update.tsx` (the production one with the 15-minute timeout, daemon-down-grace, and error-mapping). The `screens/Update.tsx` is an older simpler variant.
- **`modules/authentication/SessionExpiredDialog.tsx`** and **`modules/authentication/SessionAboutToExpireDialog.tsx`** are the always-on-top auxiliary windows. Today they're only triggered via the DEV-only "Development" tab in Settings (`SettingsDevelopment.tsx`) — a daemon-status hook (status `SessionExpired`, plus a future "about-to-expire" signal) will drive them later. Sign-in / Stay-connected emit `EventTriggerLogin` so the main window's `startLogin()` orchestrator handles the SSO flow; Logout uses `Connection.Logout({profileName, username})`.
- **`screens/QuickActions.tsx`** is wired to `/quick` in the route table but nothing on the Go side currently navigates there.
- **`UpdateAvailableBanner`** is force-enabled via `FORCE_UPDATE_AVAILABLE = true` and additionally TODO-commented for the "only when management has auto updates enabled + force updates is disabled" case.
- **`lib/MainModuleContext.tsx`** is exported but unused. Candidate for deletion.

## Wails Go API reference

Full per-service binding signatures, push-event payloads, and model field shapes live in `WAILS-API.md` (sibling). Every service method returns `$CancellablePromise<T>` — `await` and ignore `.cancel()` in practice. Regenerate bindings via `pnpm bindings` after any Go-side change.

## Useful references

- `WAILS-API.md` (sibling) — full binding signatures, push events, and model shapes.
- Wails v3 dialog signatures: `node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails v3 docs (may 403 from some clients): https://v3.wails.io/
- `../CLAUDE.md` for Go-side conventions, service registration, profile-switching policy, and Linux tray internals.
