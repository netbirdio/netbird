import { useEffect } from "react";

export type Shortcut = {
    key: string; // e.g. "k", "Escape", "/"
    cmd?: boolean; // requires Cmd (mac) / Ctrl (win/linux)
    shift?: boolean;
    alt?: boolean;
    // When true (default), preventDefault is called on a match.
    preventDefault?: boolean;
};

// Listens for a keyboard shortcut on the window and invokes `callback` on
// match. Disable conditionally via `enabled` to avoid stealing keys while a
// dialog/panel is in the foreground.
export const useKeyboardShortcut = (
    shortcut: Shortcut,
    callback: () => void,
    enabled = true,
) => {
    useEffect(() => {
        if (!enabled) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key.toLowerCase() !== shortcut.key.toLowerCase()) return;
            const mod = e.metaKey || e.ctrlKey;
            if (!!shortcut.cmd !== mod) return;
            if (!!shortcut.shift !== e.shiftKey) return;
            if (!!shortcut.alt !== e.altKey) return;
            if (shortcut.preventDefault !== false) e.preventDefault();
            callback();
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [
        shortcut.key,
        shortcut.cmd,
        shortcut.shift,
        shortcut.alt,
        shortcut.preventDefault,
        callback,
        enabled,
    ]);
};

// True on macOS — use the ⌘ glyph; otherwise show "Ctrl".
export const isMac =
    typeof navigator !== "undefined" &&
    /Mac|iPhone|iPad|iPod/i.test(navigator.platform);

export const formatShortcut = (shortcut: Shortcut): string => {
    const parts: string[] = [];
    if (shortcut.cmd) parts.push(isMac ? "⌘" : "Ctrl");
    if (shortcut.shift) parts.push(isMac ? "⇧" : "Shift");
    if (shortcut.alt) parts.push(isMac ? "⌥" : "Alt");
    parts.push(shortcut.key.length === 1 ? shortcut.key.toUpperCase() : shortcut.key);
    return parts.join(isMac ? "" : "+");
};
