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
import { Events } from "@wailsio/runtime";
import { Preferences, Theme } from "@bindings/services";
import { type Theme as ThemePref, type UIPreferences } from "@bindings/preferences/models.js";

export type ThemePreference = "system" | "light" | "dark";

const PREF_KEY = "nb-theme-pref";
const isPreference = (v: unknown): v is ThemePreference =>
    v === "system" || v === "light" || v === "dark";

const initialSystemDark = (): boolean =>
    window.matchMedia("(prefers-color-scheme: dark)").matches;

type ThemeContextValue = {
    theme: ThemePreference;
    resolvedDark: boolean;
    setTheme: (theme: ThemePreference) => Promise<void>;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export const ThemeProvider = ({ children }: { children: ReactNode }) => {
    const [theme, setThemeState] = useState<ThemePreference>(() => {
        try {
            const mirrored = localStorage.getItem(PREF_KEY);
            if (isPreference(mirrored)) return mirrored;
        } catch {
            /* fall through */
        }
        return "system";
    });
    const [systemDark, setSystemDark] = useState<boolean>(initialSystemDark);
    const themeRef = useRef(theme);
    themeRef.current = theme;
    // Blocks the initial Preferences.Get snapshot from overwriting newer updates.
    const supersededRef = useRef(false);

    useEffect(() => {
        let cancelled = false;
        Preferences.Get()
            .then((prefs) => {
                if (cancelled || supersededRef.current) return;
                if (isPreference(prefs?.theme)) setThemeState(prefs.theme);
            })
            .catch((err: unknown) => console.warn("[ThemeContext] load preferences failed", err));
        Theme.SystemDarkMode()
            .then((dark) => {
                if (!cancelled) setSystemDark(dark);
            })
            .catch((err: unknown) => console.warn("[ThemeContext] SystemDarkMode failed", err));

        // Cross-window sync: a flip in the settings window reaches every window.
        const offPrefs = Events.On("netbird:preferences:changed", (e: { data?: UIPreferences }) => {
            if (isPreference(e.data?.theme)) {
                supersededRef.current = true;
                setThemeState(e.data.theme);
            }
        });
        const offSystem = Events.On(
            "netbird:system-theme:changed",
            (e: { data?: { dark?: boolean } }) => {
                if (typeof e.data?.dark === "boolean") setSystemDark(e.data.dark);
            },
        );
        return () => {
            cancelled = true;
            offPrefs();
            offSystem();
        };
    }, []);

    const resolvedDark = theme === "dark" || (theme === "system" && systemDark);

    useEffect(() => {
        document.documentElement.classList.toggle("dark", resolvedDark);
        document.documentElement.classList.toggle("light", !resolvedDark);
        try {
            localStorage.setItem(PREF_KEY, theme);
        } catch {
            /* preference mirror is best-effort */
        }
    }, [theme, resolvedDark]);

    // Optimistic; reverts on persist failure so UI matches the stored pref.
    const setTheme = useCallback(async (next: ThemePreference) => {
        const prev = themeRef.current;
        supersededRef.current = true;
        setThemeState(next);
        try {
            await Preferences.SetTheme(next as ThemePref);
        } catch (err) {
            setThemeState(prev);
            throw err;
        }
    }, []);

    const value = useMemo<ThemeContextValue>(
        () => ({ theme, resolvedDark, setTheme }),
        [theme, resolvedDark, setTheme],
    );

    return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export const useTheme = () => {
    const ctx = useContext(ThemeContext);
    if (!ctx) throw new Error("useTheme must be used inside ThemeProvider");
    return ctx;
};
