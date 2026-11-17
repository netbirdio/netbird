import { useEffect, useState } from "react";

// Tracks the user's current input modality (keyboard vs pointer) at module
// scope, mirroring what @react-aria/interactions does. Radix programmatically
// focuses elements like Tabs triggers and Select triggers, which makes the
// browser's :focus-visible heuristic light up on mouse-driven interactions too.
// Gating focus styles on this hook lets us only paint a focus ring when the
// user is actually navigating with the keyboard.
// See react-aria's useFocusVisible for context.

type Modality = "keyboard" | "pointer";

let currentModality: Modality = "pointer";
const subscribers = new Set<(m: Modality) => void>();

const setModality = (m: Modality) => {
    if (m === currentModality) return;
    currentModality = m;
    subscribers.forEach((cb) => cb(m));
};

const isKeyboardEvent = (e: KeyboardEvent) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return false;
    return e.key === "Tab" || e.key === "Escape" || e.key.startsWith("Arrow");
};

if (globalThis.window !== undefined) {
    globalThis.addEventListener(
        "keydown",
        (e) => {
            if (isKeyboardEvent(e)) setModality("keyboard");
        },
        true,
    );
    globalThis.addEventListener("pointerdown", () => setModality("pointer"), true);
}

export const useFocusVisible = (): boolean => {
    const [visible, setVisible] = useState(currentModality === "keyboard");
    useEffect(() => {
        setVisible(currentModality === "keyboard");
        const cb = (m: Modality) => setVisible(m === "keyboard");
        subscribers.add(cb);
        return () => {
            subscribers.delete(cb);
        };
    }, []);
    return visible;
};
