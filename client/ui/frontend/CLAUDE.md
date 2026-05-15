# NetBird Wails UI — Frontend Working Notes

This is the React/TS frontend for the Wails v3 desktop UI. It runs inside the main Wails webview plus two auxiliary windows (`/#/settings` and `/#/browser-login`) opened by Go (`services/windowmanager.go`). For Go-side conventions and the daemon gRPC layer see `../CLAUDE.md`.

> **Work in progress.** Big chunks of the UI are still mocked, prototyped, or duplicated across screens that pre-date the current AppLayout. Anything marked "prototype" / "mocked" / "legacy" below should be assumed half-wired. The polished surface today is: the main connect toggle, the Settings window, the debug-bundle flow, the auto-update overlay, and the profile selector. Everything else is in flight.

## Stack

- **React 18** with `react-dom/client` + `<React.StrictMode>` (app.tsx).
- **TypeScript 5.7**, `"strict": true`, `noUnusedLocals: true`, `noImplicitAny: false`, `jsx: react-jsx`.
- **Vite 6** + `@vitejs/plugin-react`. Wails ships its own Vite plugin (`@wailsio/runtime/plugins/vite`) that's wired in for binding regen / runtime injection.
- **React Router v7** (`HashRouter` — Wails serves a static bundle so hash-based routing avoids server-side fallback).
- **Tailwind CSS 3** with `darkMode: "class"`. Class-merging via `cn(...inputs)` (`src/lib/cn.ts` — `twMerge(clsx(inputs))`).
- **Radix UI primitives** for Dialog / DropdownMenu / Popover / RadioGroup / ScrollArea / Switch / Tabs / Tooltip / VisuallyHidden / Label.
- **framer-motion** for the central connect-toggle animation only.
- **lucide-react** for icons. **chroma-js** for the deterministic-color helper. **cmdk** is installed but not currently used.
- **`@wailsio/runtime`** for `Dialogs`, `Events`, `Browser`, `Window` APIs.
- **Package manager: pnpm** (`pnpm-lock.yaml`). No `package-lock.json` / `yarn.lock`.

Scripts (`package.json`):

```
pnpm dev            # vite dev server (port 9245, host 127.0.0.1)
pnpm build:dev      # tsc + vite build, mode=development, --minify false
pnpm build          # tsc + vite build, mode=production
pnpm preview        # vite preview
pnpm typecheck      # tsc --noEmit
pnpm format         # prettier write on src/**
pnpm format:check
```

`task dev` from `client/ui/` starts the Wails dev harness, which in turn runs `vite` (port `WAILS_VITE_PORT || 9245`).

## Path aliases

`tsconfig.json` and `vite.config.ts` agree on two aliases:

| Alias | Resolves to |
|---|---|
| `@/*` | `src/*` |
| `@bindings/*` | `bindings/github.com/netbirdio/netbird/client/ui/*` |

So `import { Connection } from "@bindings/services"` and `import type { Status } from "@bindings/services/models.js"` are the canonical imports. **Don't** hand-write deep `../../bindings/github.com/...` paths — a few legacy screens (`screens/Profiles.tsx`, `pages/Update.tsx`) still do; treat that as a smell.

Bindings are regenerated from Go via `wails3 generate bindings -clean=true -ts` from `client/ui/`. Don't edit anything under `bindings/`.

## Routing (app.tsx)

`HashRouter` with the following routes:

| Path | Component | Layout | Where it opens |
|---|---|---|---|
| `/` | `Main` | `AppLayout` | Main window default route |
| `/quick` | `QuickActions` | none | Standalone — **prototype**, not currently invoked by the Go side |
| `/browser-login` | `BrowserLogin` | none | Auxiliary window (Go `WindowManager.OpenBrowserLogin`) |
| `/update` | `Update` (pages) | none | Main window during enforced-update install |
| `/session-expired` | `SessionExpired` | none | Standalone — **prototype**, no buttons wired |
| `/settings` | `Settings` | `SettingsLayout` | Auxiliary window (Go `WindowManager.OpenSettings`) |
| `*` | `<Navigate to="/">` | `AppLayout` | Catch-all |

`AppLayout` wraps `Header + <Outlet/>` in this provider order: `AppearanceProvider → ProfileProvider → DebugBundleProvider → ClientVersionProvider`. The order matters — `DebugBundleProvider` reads `useProfile`, and `ClientVersionProvider` paints the `<UpdatingOverlay/>` so it has to be outermost in terms of z-index but innermost in the tree.

`SettingsLayout` uses the same provider stack minus the `Header`. It also reserves a 38px `wails-draggable` strip at the top so the macOS traffic-light buttons (the window uses `MacTitleBarHiddenInset`) don't overlap content.

## Directory layout (src/)

```
app.tsx               # entry, routes, <SkeletonTheme>, welcome() console banner
globals.css           # Tailwind layers + custom CSS variables
vite-env.d.ts

assets/               # flags/, fonts/, logos/ (svg)
components/           # presentational primitives — see "Components" below
hooks/                # useStatus.ts (currently the only hook here)
layouts/              # AppLayout, SettingsLayout, Header, Main, MainRightSide,
                      # Navigation, ConnectionStatus, ConnectionStatusSwitch
lib/                  # cn (tailwind merge), color (hash → hex), welcome (console art),
                      # MainModuleContext (unused legacy)
modules/              # feature folders that own their own contexts/state
  appearance/         # AppearanceContext (localStorage)
  auto-update/        # ClientVersionContext + overlays/banners/badges
  debug-bundle/       # useDebugBundle hook + Provider wrapper
  peers/              # Peers UI (currently mockPeers; not wired to daemon data)
  profile/            # ProfileContext
  settings/           # Settings root + per-tab files + SettingsContext + accent egg
  skeletons/          # SkeletonSettings
pages/                # full-screen single-purpose pages routed via app.tsx
  BrowserLogin.tsx    # auxiliary window content
  SessionExpired.tsx  # prototype, no wiring
  Update.tsx          # enforced-update install screen (real one)
  Debug.tsx           # legacy debug bundle UI, superseded by SettingsTroubleshooting
screens/              # in-window screens (mostly legacy; pre-AppLayout era)
  Status.tsx          # legacy detailed status page (not in current route table)
  Peers.tsx           # legacy peer-detail UI (uses real Peers.Get data)
  Networks.tsx        # legacy networks UI
  Profiles.tsx        # uses ProfileSwitcher.SwitchActive (current preferred path)
  Settings.tsx        # legacy — superseded by modules/settings/Settings.tsx
  Update.tsx          # legacy update page (different from pages/Update.tsx)
  QuickActions.tsx    # legacy quick-action panel
  Debug.tsx           # legacy
```

The split between `pages/`, `screens/`, and `modules/` is historical and not load-bearing. Today: `modules/` owns the polished AppLayout-shell-driven UI, `pages/` owns the few routes that live outside that shell, and `screens/` is the unsorted legacy bucket. Don't add new code under `screens/` — pick `pages/` (own route, no shell) or `modules/<feature>/` (lives inside the shell).

## Generated bindings

Re-exported from `@bindings/services/index.ts`:

```ts
import {
  Connection, Debug, Forwarding, Networks, Peers,
  ProfileSwitcher, Profiles, Settings, Update, WindowManager,
} from "@bindings/services";

import type {
  ActiveProfile, Config, ConfigParams, DebugBundleParams, DebugBundleResult,
  Features, ForwardingRule, LocalPeer, LogLevel, LoginParams, LoginResult,
  LogoutParams, Network, PeerLink, PeerStatus, PortInfo, PortRange, Profile,
  ProfileRef, SelectNetworksParams, SetConfigParams, Status, SystemEvent,
  UpParams, UpdateAvailable, UpdateProgress, UpdateResult, WaitSSOParams,
} from "@bindings/services/models.js";
```

Every service method returns a `$CancellablePromise<T>` (Wails3 wrapper) — call `.cancel()` to abort the underlying gRPC call. In practice we `await` them and never call `.cancel()`; the few stream-driven cases use `AbortController` (see `useDebugBundle`).

## Wails event bus

Subscribe with `Events.On(name, handler)`. The handler receives `{ data: <typed payload> }`. The event name strings live next to their usage (no central registry on the TS side).

| Event name (string) | Payload | Emitted by | Consumed by |
|---|---|---|---|
| `netbird:status` | `Status` | `services/peers.go statusStreamLoop` | `hooks/useStatus` |
| `netbird:event` | `SystemEvent` | `services/peers.go toastStreamLoop` | Not currently subscribed on the TS side — Status is read via `useStatus().status.events` instead. The tray (Go) consumes it for OS notifications. |
| `netbird:update:available` | `UpdateAvailable` | `services/peers.go fanOutUpdateEvents` | Not directly subscribed on the TS side; `ClientVersionContext` derives `updateVersion` from `status.events` metadata instead. |
| `netbird:update:progress` | `UpdateProgress` | same | Same — drives the tray; Go side opens the `/update` route. |
| `browser-login:cancel` | (no payload) | `BrowserLogin` page (frontend) when user clicks Cancel **or** Go `services/windowmanager.go` when user closes the BrowserLogin window | `layouts/ConnectionStatusSwitch.tsx`'s `startLogin()` to abort the in-flight `WaitSSOLogin` |
| `trigger-login` | (no payload) | Reserved (`services.EventTriggerLogin`); not currently used by the frontend |

If you wire a new daemon-event subscriber on the TS side, prefer subscribing once at the context level rather than per-screen — the Wails event bus is process-wide and each `Events.On` adds an emit-time fan-out.

## Contexts and state

State that crosses screens / windows lives in context. Each provider is mounted exactly once inside `AppLayout` or `SettingsLayout`.

### `useStatus` (hooks/useStatus.ts)

Returns `{ status, error, refresh }`. Fetches `Peers.Get()` once, then re-renders on every `netbird:status` push. `refresh()` is for forcing a re-read after a user action (Connect / Disconnect) so the UI doesn't lag the event stream by a few hundred ms.

### `ProfileContext` (modules/profile/ProfileContext.tsx)

Single source of truth for `username`, `activeProfile`, `profiles`. Exposes `refresh`, `switchProfile`, `addProfile`, `removeProfile`, `logoutProfile`.

**Caveat:** `ProfileContext.switchProfile` implements the reconnect policy in TS (Switch + conditional Down/Up gated on previous Connected/Connecting). The Go-side `ProfileSwitcher.SwitchActive` does the same thing **plus** drives the optimistic-Connecting paint via `Peers.BeginProfileSwitch`. Prefer `ProfileSwitcher.SwitchActive` for new call sites — `screens/Profiles.tsx` already does. The duplicate logic in `ProfileContext` is on the cleanup list.

### `SettingsContext` (modules/settings/SettingsContext.tsx)

Loads `SettingsSvc.GetConfig` for the active profile, then debounces every `setField` write (`SAVE_DEBOUNCE_MS = 400`). API:

- `setField(k, v)` — optimistic update + debounced save. Use for toggles.
- `saveField(k, v)` — flush pending + save immediately. Use for explicit Save buttons.
- `saveFields(partial)` — same as `saveField` but for multiple keys at once (used by the Advanced tab's batched save).
- `saveNow()` — flush pending without changing values.

While `config` is `null` the provider renders `<SkeletonSettings/>` instead of children — the actual tabs never need to handle a null config.

**PSK mask quirk:** The daemon returns existing pre-shared keys as `"**********"` in `GetConfig`. Sending the mask back round-trips it into the saved config and `wgtypes.ParseKey` fails on the next connect. `save` drops the field when it equals `"**********"` so an unrelated toggle save doesn't corrupt the stored PSK.

### `AppearanceContext` (modules/appearance/AppearanceContext.tsx)

Pure-frontend UI preferences persisted to `localStorage` under `netbird:appearance`. Fields: `connectionLayout` (`"default" | "switch"`), `expanded` (bool — drives the wide / narrow window mode), `showPeersNav`, `showResourcesNav`, `showExitNodeNav`, `showProfileSelector`, `showSettingsButton`. `Header.tsx` writes `expanded` and resizes the OS window to match (`Window.SetSize(925|380, 615)`).

### `DebugBundleProvider` + `useDebugBundle` (modules/debug-bundle/)

Stateful hook driving the debug-bundle flow. Wrapped in a context so the troubleshooting tab inside the Settings window keeps the same stage if the user navigates away and back. Stages:

```
idle → preparing-trace → reconnecting → capturing (per-second countdown) →
restoring-level → bundling → uploading → done
```

Cancellable via `AbortController` from any stage. On cancel the original log level is restored best-effort. `NETBIRD_UPLOAD_URL = https://upload.debug.netbird.io/upload-url` is hardcoded.

### `ClientVersionContext` (modules/auto-update/ClientVersionContext.tsx)

Reads `Status.events`, finds the most recent event whose metadata carries `new_version_available`, and exposes `{ updateAvailable, updateVersion, triggerUpdate, updating, updateError, dismissUpdateError }`. Mounts `<UpdateAvailableBanner/>` and the `<UpdatingOverlay/>` so any screen inherits the overlay without opting in.

**Dev preview flags at the top of the file** (flip and save to preview UI states without involving the daemon):

```ts
const FORCE_UPDATE_AVAILABLE = true;    // currently TRUE — banner is forced on
const FORCE_UPDATING = false;
const FORCE_VERSION = "0.65.0";
const HIDE_UPDATE_AVAILABLE = false;    // hard-hide everything regardless of state
const FORCE_ERROR: ForceError = null;   // "timeout" | "cancel" | "fail" | null
const FORCE_ERROR_MSG = "installer exited with code 1";
```

`FORCE_UPDATE_AVAILABLE = true` means the banner shows in production builds too right now. Flip it back to `false` before a real release. `UpdateAvailableBanner` additionally returns null in `import.meta.env.DEV` to avoid noise during `pnpm dev`.

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

`src/components/` holds presentational primitives (no daemon RPCs, no router):

- **Form / interactive:** `Button`, `IconButton`, `Input` (label + help text + reveal toggle + suffix + readonly + copy slot), `Switch`, `ToggleSwitch`, `FancyToggleSwitch` (label + helpText + value), `Label`, `HelpText`, `SearchInput`, `Tabs`, `VerticalTabs`, `CardSelect`, `CardNavItem`, `Card`.
- **Layout / overlays:** `Dialog` (Radix wrapper with `Root/Trigger/Content/Title/Description/Footer`), `BottomSheet`, `Tooltip`, `StatusPanel`.
- **Domain-specific:** `NetBirdConnectToggle` (the big animated brand circle — framer-motion + tailwind keyframes), `ProfileSelector`, `NewProfileDialog`, `Avatar`.

Settings rows mostly use `FancyToggleSwitch` inside `<SectionGroup title=…>`. Section group dimming is handled with `disabled` (greyed + `pointer-events-none`).

In-app modals (NewProfileDialog, the delete-profile confirm in `screens/Profiles.tsx`) use the Radix `Dialog` primitive inside the main webview. The two auxiliary OS windows (Settings, BrowserLogin) are created by Go via `WindowManager`, not by frontend code.

## Dialogs convention (recap)

Errors surface via `Dialogs.Error` from `@wailsio/runtime` with an action-named title:

```ts
await Dialogs.Error({
  Title: "Save Settings Failed",     // not "Error"
  Message: e instanceof Error ? e.message : String(e),
});
```

Confirmations use `Dialogs.Warning` with explicit `Buttons` and compare against the **Label string**, not an index:

```ts
const r = await Dialogs.Warning({
  Title: "Delete Profile",
  Message: `Delete "${name}"?`,
  Buttons: [{ Label: "Cancel", IsCancel: true }, { Label: "Delete", IsDefault: true }],
});
if (r !== "Delete") return;
```

When **not** to use native dialogs: inline form validation, transient link errors on the dashboard, "partial success" notes inside an otherwise-OK flow. See `../CLAUDE.md` for the full rules. The settings management-URL switch is a good example: `useManagementUrl` shows inline URL-format errors but throws up a `Dialogs.Warning` confirmation when the user is about to flip from self-hosted to NetBird Cloud (because that forces a reconnect/re-login).

## Tailwind tokens

Custom colors in `tailwind.config.ts`:

- `nb-gray` — main neutral palette, 50–960. `nb-gray-950` (#181a1d) is the app background; tabs/cards step through 900/910/920/925/935/940 as you go deeper. `DEFAULT` is `nb-gray-950`.
- `netbird` — brand orange. `DEFAULT` is `#f68330` (500-ish). Used for primary buttons, focused tab borders, the connect-toggle border ring.
- `gray`, `red`, `yellow`, `green`, `blue`, `indigo`, `purple`, `pink` — Flowbite-style 50–900 palettes used in the legacy screens (`screens/*`). Avoid in new code — stick to `nb-gray` + `netbird` + the semantic dot colors (`green-500`, `red-500`, `yellow-500`).

Background image `bg-conic-netbird` and keyframes `pulse-reverse` / `spin-slow` / `ping-slow` (plus the animations `animate-pulse-slow`, `animate-pulse-slower`, `animate-spin-slow`, `animate-ping-slow`) are used by `NetBirdConnectToggle`.

Fonts: Inter Variable (sans) + JetBrains Mono Variable (mono) — both shipped under `src/assets/fonts/`.

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
- **`pages/SessionExpired.tsx`** is fully rendered but the Sign-in / Later buttons have no onClick handlers yet.
- **`screens/QuickActions.tsx`** is wired to `/quick` in the route table but nothing on the Go side currently navigates there.
- **`UpdateAvailableBanner`** is force-enabled via `FORCE_UPDATE_AVAILABLE = true` and additionally TODO-commented for the "only when management has auto updates enabled + force updates is disabled" case.
- **`lib/MainModuleContext.tsx`** is exported but unused. Candidate for deletion.
- **`ConnectionStatus.tsx`** (the non-Switch variant of the main toggle) is local-state-only — it does not call `Connection.Up/Down` and shows hardcoded `peer-hostname.netbird.cloud` / `192.168.0.1`. It's a visual prototype the user can flip to via `connectionLayout` in `AppearanceContext`; **don't rely on it for real connect/disconnect behavior**. The real one is `ConnectionStatusSwitch.tsx`.
- **`SettingsAccent`** is a 10-clicks-on-the-version-label easter egg that renders a falling-`TEAMNETBIRD` canvas overlay for 9 seconds. Kept on purpose.

## Wails Go API reference

Quick reference for every binding method and model shape exposed to the frontend. Generated from `services/*.go` via `wails3 generate bindings -clean=true -ts` — regenerate after any Go-side change. Authoritative source is always `bindings/github.com/netbirdio/netbird/client/ui/services/*.ts`.

Every method returns `$CancellablePromise<T>` (a Wails3 wrapper around `Promise`). Call `.cancel()` to abort the underlying gRPC call; in practice we just `await` and let it run.

### Imports

```ts
// Services
import {
  Connection, Peers, ProfileSwitcher, Profiles,
  Settings, Networks, Forwarding, Debug, Update, WindowManager,
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
```

### Push events

Subscribe with `Events.On(name, handler)` from `@wailsio/runtime`. Handlers receive `{ data: <payload> }`.

| Event | Payload | Fires on |
|---|---|---|
| `netbird:status` | `Status` | Daemon SubscribeStatus snapshot — connection-state change, peer-list change, address change, mgmt/signal flip. Synthetic `StatusDaemonUnavailable` is emitted when the gRPC socket is unreachable, and a synthetic `Connecting` is emitted at the start of an active profile switch. |
| `netbird:event` | `SystemEvent` | One push per daemon SubscribeEvents item (DNS / network / authentication / connectivity / system). Used by the tray for OS toasts; the TS side reads events through `Status.events` instead. |
| `netbird:update:available` | `UpdateAvailable` | Daemon detected a new version (fan-out of the `new_version_available` metadata key). |
| `netbird:update:progress` | `UpdateProgress` | Daemon enforced-update install progress (`action: "show"` etc.). |
| `browser-login:cancel` | (none) | Either the user closed the `BrowserLogin` window (Go-emitted) or the page's Cancel button (frontend-emitted). |
| `trigger-login` | (none) | Reserved by the tray for asking the frontend to start an SSO flow; not currently wired on the TS side. |

The two stream loops behind `netbird:status` and `netbird:event` start automatically — `main.go` calls `peers.Watch(context.Background())` at boot. `Peers.Watch` is still exported but the frontend doesn't need to invoke it.

### `Connection`

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

### `Peers`

```ts
Peers.Get(): Promise<Status>            // one-shot snapshot
Peers.Watch(): Promise<void>            // already invoked from main.go
Peers.BeginProfileSwitch(): Promise<void>
Peers.CancelProfileSwitch(): Promise<void>
```

`BeginProfileSwitch` and `CancelProfileSwitch` are normally driven by `ProfileSwitcher` / the tray, not the frontend.

### `ProfileSwitcher`

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

### `Profiles`

```ts
Profiles.Username(): Promise<string>            // current OS username
Profiles.List(username: string): Promise<Profile[]>
Profiles.GetActive(): Promise<ActiveProfile>
Profiles.Switch(p: ProfileRef): Promise<void>   // raw daemon RPC; prefer ProfileSwitcher.SwitchActive
Profiles.Add(p: ProfileRef): Promise<void>
Profiles.Remove(p: ProfileRef): Promise<void>
```

`Profile.email` is populated by the **UI process** reading the per-profile state file (`~/Library/Application Support/netbird/<name>.state.json` on macOS), not by the daemon — the daemon runs as root and can't read user-owned files.

### `Settings`

```ts
Settings.GetConfig(p: ConfigParams): Promise<Config>
Settings.SetConfig(p: SetConfigParams): Promise<void>     // partial update
Settings.GetFeatures(): Promise<Features>                 // operator-disabled UI sections
```

`SetConfig` is a partial update: only fields you set are pushed to the daemon. `profileName` + `username` are always required; the typed fields in `SetConfigParams` are optional (`field?: T | null`). `managementUrl` and `adminUrl` are always-string for historical reasons.

**PSK mask quirk:** `GetConfig` returns existing pre-shared keys as `"**********"`. If you send the mask back, `wgtypes.ParseKey` fails on the next connect. `SettingsContext.save` drops the field when it equals `"**********"`. See `modules/settings/SettingsContext.tsx`.

`SetConfigParams` carries one field that `Config` does not: `disableFirewall`. There's no current GET path for it.

### `Networks`

```ts
Networks.List(): Promise<Network[]>
Networks.Select(p: SelectNetworksParams): Promise<void>
Networks.Deselect(p: SelectNetworksParams): Promise<void>
```

`SelectNetworksParams.append=true` merges into the existing selection; `false` replaces. `all=true` ignores `networkIds` and targets every network (Select-All / Deselect-All).

Exit-node filter: `range === "0.0.0.0/0" || range === "::/0"`. Domain network: `domains.length > 0`. CIDR overlap check is client-side.

### `Forwarding`

```ts
Forwarding.List(): Promise<ForwardingRule[]>
```

`PortInfo` is a daemon-side oneof — exactly one of `port?: number` or `range?: PortRange` is populated. `protocol` is the lowercase daemon string (`"tcp"` / `"udp"`).

### `Debug`

```ts
Debug.GetLogLevel(): Promise<LogLevel>
Debug.SetLogLevel(lvl: LogLevel): Promise<void>
Debug.Bundle(p: DebugBundleParams): Promise<DebugBundleResult>
Debug.RevealFile(path: string): Promise<void>          // OS file-manager focus
```

**Log level case sensitivity bug:** `proto.LogLevel_value` is keyed on uppercase enum names (`"TRACE"`, `"DEBUG"`, `"INFO"`, `"WARN"`, `"ERROR"`, `"PANIC"`, `"FATAL"`, `"UNKNOWN"`). `Debug.SetLogLevel` calls `proto.LogLevel_value[lvl.Level]` and falls back to `INFO` on miss. `useDebugBundle` currently passes `"trace"` (lowercase), which silently maps to `INFO` — the trace-capture flow doesn't actually raise the log level today. To raise to trace, pass `{ level: "TRACE" }`. Fix on the cleanup list.

`Debug.Bundle` uploads when `uploadUrl != ""`. Result fields: `path` (local copy), `uploadedKey` (set on success), `uploadFailureReason` (set on upload failure — the local copy is still saved).

### `Update`

```ts
Update.Trigger(): Promise<UpdateResult>             // start the install
Update.GetInstallerResult(): Promise<UpdateResult>  // poll the outcome (long-running)
Update.Quit(): Promise<void>                        // 100ms later, app.Quit()
```

Typical enforced-update flow on the `/update` route: call `Trigger` once, then poll `GetInstallerResult` every 2s with a 15-minute total timeout. On `success: true` call `Quit`. On `success: false` show `errorMsg`. If the gRPC poll itself starts failing for `DAEMON_DOWN_GRACE_MS` (5s), treat that as success and quit too — the installer commonly takes the daemon offline mid-upgrade. See `pages/Update.tsx` for the canonical implementation.

### `WindowManager`

```ts
WindowManager.OpenSettings(): Promise<void>
WindowManager.OpenBrowserLogin(uri: string): Promise<void>   // uri appended as ?uri=…
WindowManager.CloseBrowserLogin(): Promise<void>
```

Both auxiliary windows are created on first open and destroyed on close (mutex-guarded singleton). The BrowserLogin window's red-X close fires the `browser-login:cancel` event so `startLogin()` can tear down the pending daemon `WaitSSOLogin`.

### Daemon `Status.status` values

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

### Model field reference

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

## Useful references

- Wails v3 dialog signatures: `node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails v3 docs (may 403 from some clients): https://v3.wails.io/
- `../CLAUDE.md` for Go-side conventions, service registration, profile-switching policy, and Linux tray internals.
