import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Window } from "@wailsio/runtime";
import { Preferences } from "@bindings/services";
import { ViewMode as ViewModePref } from "@bindings/preferences/models.js";

export type ViewMode = "default" | "advanced";

// Window widths per view. Height stays at whatever the window was first
// created with — we deliberately don't pass a fixed height to
// Window.SetSize because Wails' macOS implementation interprets it as the
// outer frame (windowSetSize → setFrame:), while the initial creation
// uses initWithContentRect:. The two differ by one title-bar height
// (~28px), so re-asserting 640 here would chop ~28px off the content
// area on the first switch and visually shift everything inside.
export const VIEW_WIDTH: Record<ViewMode, number> = {
    default: 380,
    advanced: 900,
};

type ViewModeContextValue = {
    viewMode: ViewMode;
    setViewMode: (mode: ViewMode) => void;
};

const ViewModeContext = createContext<ViewModeContextValue | null>(null);

export const ViewModeProvider = ({ children }: { children: ReactNode }) => {
    const [viewMode, setMode] = useState<ViewMode>("default");

    // Hydrate from the persisted preference. The Go side has already sized
    // the main window to match (see main.go), so this only catches the
    // React state and dropdown checkmark up — no resize is triggered here.
    useEffect(() => {
        let cancelled = false;
        void Preferences.Get()
            .then((prefs) => {
                if (cancelled) return;
                const saved = prefs?.viewMode as ViewMode | undefined;
                if (saved === "default" || saved === "advanced") {
                    setMode(saved);
                }
            })
            .catch(() => {});
        return () => {
            cancelled = true;
        };
    }, []);

    const setViewMode = useCallback(
        (mode: ViewMode) => {
            setMode((prev) => {
                if (prev === mode) return prev;
                void (async () => {
                    // Reuse the live frame height instead of asserting a
                    // constant — keeps content area stable across switches
                    // (see VIEW_WIDTH comment above).
                    const size = await Window.Size().catch(() => null);
                    const width = VIEW_WIDTH[mode];
                    const height = size?.height ?? 640;
                    await Window.SetSize(width, height).catch(() => {});
                })();
                void Preferences.SetViewMode(mode as unknown as ViewModePref).catch(() => {});
                return mode;
            });
        },
        [],
    );
    return (
        <ViewModeContext.Provider value={{ viewMode, setViewMode }}>
            {children}
        </ViewModeContext.Provider>
    );
};

export const useViewMode = () => {
    const ctx = useContext(ViewModeContext);
    if (!ctx) throw new Error("useViewMode must be used inside ViewModeProvider");
    return ctx;
};
