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
import { Window } from "@wailsio/runtime";
import { Preferences } from "@bindings/services";
import { ViewMode as ViewModePref } from "@bindings/preferences/models.js";
import { isLinux } from "@/lib/platform";
import { enqueueWindowResize } from "@/hooks/useLinuxHiDpiWindow";

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

    useEffect(() => {
        let cancelled = false;
        Preferences.Get()
            .then((prefs) => {
                if (cancelled) return;
                const saved = prefs?.viewMode as ViewMode | undefined;
                if (saved === "default" || saved === "advanced") {
                    modeRef.current = saved;
                    setMode(saved);
                }
            })
            .catch((err: unknown) =>
                console.warn("[ViewModeContext] load preferences failed", err),
            );
        return () => {
            cancelled = true;
        };
    }, []);

    // Resize before flipping React state, else the layout paints into a window that hasn't grown yet.
    // The resize goes through the shared queue so it cannot interleave with the
    // mount-time HiDPI scaling of the same window.
    const setViewMode = useCallback((mode: ViewMode) => {
        if (modeRef.current === mode) return;
        modeRef.current = mode;
        enqueueWindowResize(async () => {
            const size = await Window.Size().catch((err: unknown) => {
                console.warn("[ViewModeContext] read window size failed", err);
                return null;
            });
            let width = VIEW_WIDTH[mode];
            // Frame-to-viewport ratio, not the raw devicePixelRatio: with
            // GDK_SCALE, GTK already scales the sizes and the ratio is 1.
            if (isLinux() && size) {
                const shrink = size.width / window.innerWidth;
                if (Number.isFinite(shrink) && shrink > 1) {
                    width = Math.round(width * shrink);
                }
            }
            const height = size?.height ?? 640;
            await Window.SetSize(width, height).catch((err: unknown) =>
                console.warn("[ViewModeContext] set window size failed", err),
            );
            setMode(mode);
            const pref =
                mode === "advanced" ? ViewModePref.ViewModeAdvanced : ViewModePref.ViewModeDefault;
            Preferences.SetViewMode(pref).catch((err: unknown) =>
                console.error("[ViewModeContext] SetViewMode failed", err),
            );
        });
    }, []);

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
