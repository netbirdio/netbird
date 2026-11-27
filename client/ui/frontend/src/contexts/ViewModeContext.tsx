import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { Events, Window } from "@wailsio/runtime";
import { Preferences } from "@bindings/services";
import { ViewMode as ViewModePref, type UIPreferences } from "@bindings/preferences/models.js";

export type ViewMode = "default" | "advanced";

// Don't pass a fixed height to Window.SetSize: macOS SetSize is frame (incl. ~28px
// title bar) while creation is content, so re-asserting a constant chops the content on first switch.
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
    const [mode, setMode] = useState<ViewMode>("default");
    const modeRef = useRef<ViewMode>("default");
    // Blocks the initial Preferences.Get snapshot from overwriting newer updates.
    const supersededRef = useRef(false);

    // Resize before flipping React state, else the layout paints into a window that hasn't grown yet.
    const applyMode = useCallback((mode: ViewMode, persist: boolean) => {
        supersededRef.current = true;
        if (modeRef.current === mode) return;
        modeRef.current = mode;
        (async () => {
            const size = await Window.Size().catch((err: unknown) => {
                console.warn("[ViewModeContext] read window size failed", err);
                return null;
            });
            const width = VIEW_WIDTH[mode];
            const height = size?.height ?? 640;
            await Window.SetSize(width, height).catch((err: unknown) =>
                console.warn("[ViewModeContext] set window size failed", err),
            );
            setMode(mode);
            if (!persist) return;
            const pref =
                mode === "advanced" ? ViewModePref.ViewModeAdvanced : ViewModePref.ViewModeDefault;
            Preferences.SetViewMode(pref).catch((err: unknown) =>
                console.error("[ViewModeContext] SetViewMode failed", err),
            );
        })().catch((err: unknown) => console.error("[ViewModeContext] setViewMode failed", err));
    }, []);

    const setViewMode = useCallback((mode: ViewMode) => applyMode(mode, true), [applyMode]);

    useEffect(() => {
        let cancelled = false;
        Preferences.Get()
            .then((prefs) => {
                if (cancelled || supersededRef.current) return;
                const saved = prefs?.viewMode as ViewMode | undefined;
                if (saved === "default" || saved === "advanced") {
                    modeRef.current = saved;
                    setMode(saved);
                }
            })
            .catch((err: unknown) =>
                console.warn("[ViewModeContext] load preferences failed", err),
            );
        // An MDM default changes the stored view mode while the window is open.
        const offPrefs = Events.On("netbird:preferences:changed", (e: { data?: UIPreferences }) => {
            const next = e.data?.viewMode as ViewMode | undefined;
            if (next === "default" || next === "advanced") applyMode(next, false);
        });
        return () => {
            cancelled = true;
            offPrefs();
        };
    }, [applyMode]);

    const value = useMemo<ViewModeContextValue>(
        () => ({ viewMode: mode, setViewMode }),
        [mode, setViewMode],
    );

    return <ViewModeContext.Provider value={value}>{children}</ViewModeContext.Provider>;
};

export const useViewMode = () => {
    const ctx = useContext(ViewModeContext);
    if (!ctx) throw new Error("useViewMode must be used inside ViewModeProvider");
    return ctx;
};
