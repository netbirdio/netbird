import { WindowManager } from "@bindings/services";

// Options for errorDialog. Kept as a {Title, Message} object so the many
// existing call sites read unchanged after the switch from the native OS
// MessageBox to the custom window below.
export type ErrorDialogOptions = {
    Title: string;
    Message: string;
};

// errorDialog surfaces a user-actionable failure. It opens the custom,
// frameless, always-on-top NetBird error window (modules/error/ErrorDialog.tsx
// via Go WindowManager.OpenError) — it is NOT the native OS MessageBox any
// more, despite the name.
//
// Why the native box is gone: on Windows a native MessageBox attached to a
// parent window disables that window (WS_DISABLED) for its lifetime, and the
// main window's WindowClosing hook hides instead of closing — the two raced
// and could leave the main window unable to process its close (X) button after
// an error was shown. The custom window has its own chrome and never touches
// another window's enabled state, so that class of bug is gone (and with it
// the old `Detached: true` Windows-only workaround, plus the warning/info/
// question wrappers that nothing called).
//
// Title and message must already be localised. Resolves as soon as the window
// is opened (it does not block until the user dismisses it), so `await`ing
// callers continue immediately after the dialog appears.
export function errorDialog(options: ErrorDialogOptions): Promise<void> {
    return WindowManager.OpenError(options.Title, options.Message);
}
