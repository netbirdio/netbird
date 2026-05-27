import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Window } from "@wailsio/runtime";
import { Preferences } from "@bindings/services";
import { ViewMode as ViewModePref } from "@bindings/preferences/models.js";

export type ViewMode = "default" | "advanced";

// Window dimensions per view. Height matches the Settings window (640) so
// the chrome height is identical across surfaces; width grows from the
// compact 380 default to 900 in advanced.
export const VIEW_SIZE: Record<ViewMode, { width: number; height: number }> = {
    default: { width: 380, height: 640 },
    advanced: { width: 900, height: 640 },
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
                const { width, height } = VIEW_SIZE[mode];
                void Window.SetSize(width, height).catch(() => {});
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
