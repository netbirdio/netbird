# NetBird Wails UI — Working Notes

This is the Wails v3 desktop UI for NetBird. Go services live in `services/`; the React/TS frontend lives in `frontend/`; bindings between them are generated under `frontend/bindings/`.

## Layout
- `main.go`, `tray*.go`, `grpc.go` — app entry, system tray, daemon gRPC client.
- `services/*.go` — typed Wails services exposed to JS (`Profiles`, `Settings`, `Networks`, `Peers`, `Connection`, `Debug`, `Update`, `Forwarding`). Each method becomes a TS function in `frontend/bindings/.../services/`.
- `frontend/bindings/**` — generated, do not edit by hand. Regen via `wails3 generate bindings -clean=true -ts` (from this dir). Triggered by Go code changes.
- `frontend/src/` — React app. Route table is `app.tsx`. App shell is `layouts/AppLayout.tsx`; context providers live under `modules/*/Context.tsx`.

## Daemon proto
- Proto source: `../proto/daemon.proto`. Generated Go in `../proto/*.pb.go`.
- Regen: `cd ../proto && protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative daemon.proto`
- Pinned versions (see `daemon.pb.go` header): `protoc v7.34.1`, `protoc-gen-go v1.36.6`. CI's `proto-version-check` workflow fails on mismatch.
- After proto regen, also regen Wails bindings so the TS layer picks up new fields.

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

### Custom dialogs (frameless child windows)

When the native API isn't enough (rich content, form layout, complex validation), open a regular Wails window with dialog-like options. This is done on the **Go side** — `app.Window.NewWithOptions(application.WebviewWindowOptions{...})`. Key options:
- `Parent` — attach to a parent so OS treats it as a child.
- `AlwaysOnTop: true` — float above the parent.
- `Frameless: true` — no titlebar/chrome.
- `Resizable: false` — fixed-size dialog feel.
- `Hidden: true` initially, then `dialog.Show()` + `dialog.SetFocus()`.

Modal behavior is achieved by calling `parent.SetEnabled(false)` and restoring with `parent.SetEnabled(true)` in `dialog.OnClose`. Communicate results via Wails events (`app.Event.On(...)`, `Events.Emit(...)` on the frontend) or a Go channel.

We are **not currently using custom dialogs** in this repo — the in-app modals (`NewProfileDialog`, etc.) are Radix `Dialog` primitives inside the main webview, which is fine for most flows. Reach for a custom OS window only when content must escape the main window (e.g. a separate auth window) or when modality across windows matters.

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

### Bindings & types
Always import generated bindings from `@bindings/services` and types from `@bindings/services/models.js`. The path alias is set up in `tsconfig.json` / `vite.config.ts`.

After editing any `services/*.go` (or the underlying proto), regenerate:
```
wails3 generate bindings -clean=true -ts
```

### Profile context
`modules/profile/ProfileContext.tsx` is the single source of truth for `username`, `activeProfile`, and the `profiles` list. It exposes `switchProfile`, `addProfile`, `removeProfile`, `logoutProfile`, and `refresh`. `switchProfile` mirrors `tray.go`: it always issues `Profiles.Switch`, but only calls `Connection.Down` + `Connection.Up` when the daemon was actively online (status `Connected`/`Connecting`). Calling `Up` on an `Idle`/`NeedsLogin` daemon makes it block on the daemon's internal 50s `waitForUp` and return `DeadlineExceeded`. Callers shouldn't bring the connection up themselves.

## Build / dev tasks
- `task dev` — Wails dev mode (live reload).
- `task build` — production build for the current OS (Taskfile dispatches to `darwin/`, `linux/`, `windows/`).
- `task generate:bindings` does not exist as a top-level alias — run `wails3 generate bindings -clean=true -ts` directly from this directory.

## Useful references
- Wails v3 dialog docs: https://v3.wails.io/features/dialogs/message/ and https://v3.wails.io/features/dialogs/custom/ (may 403 from some clients).
- Authoritative TS signatures: `frontend/node_modules/@wailsio/runtime/types/dialogs.d.ts`.
- Wails examples: https://github.com/wailsapp/wails/tree/master/v3/examples/dialogs
