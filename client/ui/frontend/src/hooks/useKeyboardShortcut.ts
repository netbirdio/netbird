import { useEffect } from "react";
import { isMacOS } from "@/lib/platform";

export type Shortcut = {
    key: string;
    cmd?: boolean;
    shift?: boolean;
    alt?: boolean;
    preventDefault?: boolean;
};

export const useKeyboardShortcut = (shortcut: Shortcut, callback: () => void, enabled = true) => {
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
        globalThis.addEventListener("keydown", onKey);
        return () => globalThis.removeEventListener("keydown", onKey);
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

export const formatShortcut = (shortcut: Shortcut): string => {
    // navigator.platform is empty on some WebView2 builds → misrenders ⌘ as Ctrl on Mac.
    const mac = isMacOS();
    const parts: string[] = [];
    if (shortcut.cmd) parts.push(mac ? "⌘" : "Ctrl");
    if (shortcut.shift) parts.push(mac ? "⇧" : "Shift");
    if (shortcut.alt) parts.push(mac ? "⌥" : "Alt");
    parts.push(shortcut.key.length === 1 ? shortcut.key.toUpperCase() : shortcut.key);
    return parts.join(mac ? "" : "+");
};
