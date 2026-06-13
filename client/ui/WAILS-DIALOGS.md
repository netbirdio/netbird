# Wails Dialogs (frontend, `@wailsio/runtime`)

The frontend dialog API lives in `@wailsio/runtime` as `Dialogs`. Authoritative signatures are in
`frontend/node_modules/@wailsio/runtime/types/dialogs.d.ts`.

See `CLAUDE.md` for project conventions on *when* to use these (errors vs. inline validation, confirmation flow, etc.).

## Message dialogs

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

## File dialogs

`Dialogs.OpenFile(options)` and `Dialogs.SaveFile(options)` — see `dialogs.d.ts` for the full `OpenFileDialogOptions` / `SaveFileDialogOptions` field set (filters, ButtonText, multi-select, hidden files, alias resolution, directory mode, etc).

## Per-OS behavior

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

## Frameless / custom-window dialogs (Go side)

When the native dialog API isn't enough — rich content, embedded webview, multi-screen flow — open a regular Wails window. This is done on the **Go side** via `app.Window.NewWithOptions(application.WebviewWindowOptions{...})`. Useful options:
- `Parent` — attach to a parent so OS treats it as a child.
- `AlwaysOnTop: true` — float above the parent.
- `Frameless: true` — no titlebar/chrome.
- `Resizable: false` (also `DisableResize: true` in v3) — fixed-size dialog feel.
- `Hidden: true` initially, then `dialog.Show()` + `dialog.SetFocus()`.

We **do** use this pattern, but pragmatically: `WindowManager.OpenSettings` and `OpenBrowserLogin` are regular small webview windows (not modal sheets) with no resize, hidden minimise/maximise buttons, and a translucent macOS title bar. They're not classic "OS modal dialogs"; they're just lightweight ancillary windows that look the part. Modal behaviour (`parent.SetEnabled(false)`) is intentionally not used — the user can still click back to the main window.

In-app modals (`NewProfileDialog`, delete-profile confirmation, etc.) are Radix `Dialog` primitives inside the main webview. Reach for a custom OS window only when content must escape the main window (BrowserLogin is the canonical example — its lifecycle is tied to the SSO wait) or when the window needs its own taskbar entry / dock icon.
