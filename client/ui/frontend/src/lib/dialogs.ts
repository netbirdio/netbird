import { Dialogs } from "@wailsio/runtime";

import { isWindows } from "@/lib/platform";

// Derived from the runtime rather than deep-imported: the package's exports map
// only exposes the types barrel, not "@wailsio/runtime/types/dialogs".
type MessageDialogOptions = Parameters<typeof Dialogs.Error>[0];

// On Windows a native MessageBox attached to a parent window disables that
// parent (WS_DISABLED) for the lifetime of the dialog and re-enables it on
// dismissal. When the parent is the main window — whose WindowClosing hook
// hides instead of closes (main.go) — the enable/hide sequence can race and
// leave the window unable to process its close (X) button afterwards: the user
// reports the main window can no longer be closed once an error dialog (e.g. a
// rejected login) has been shown. Detaching the dialog gives the MessageBox a
// NULL owner, so no window is ever disabled and the X keeps working.
//
// macOS keeps the attached (sheet-style) presentation — the bug is Windows-only
// and detaching there loses the sheet animation — so we only force Detached on
// Windows and leave any caller-supplied value untouched elsewhere.
function withDetached(options: MessageDialogOptions): MessageDialogOptions {
    if (options.Detached !== undefined || !isWindows()) {
        return options;
    }
    return { ...options, Detached: true };
}

export function errorDialog(options: MessageDialogOptions): Promise<string> {
    return Dialogs.Error(withDetached(options));
}

export function warningDialog(options: MessageDialogOptions): Promise<string> {
    return Dialogs.Warning(withDetached(options));
}

export function infoDialog(options: MessageDialogOptions): Promise<string> {
    return Dialogs.Info(withDetached(options));
}

export function questionDialog(options: MessageDialogOptions): Promise<string> {
    return Dialogs.Question(withDetached(options));
}
