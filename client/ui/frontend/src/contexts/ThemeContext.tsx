import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useState,
    type ReactNode,
} from "react";
import { Events } from "@wailsio/runtime";
import { Preferences, Theme } from "@bindings/services";
import { type Theme as ThemePref, type UIPreferences } from "@bindings/preferences/models.js";

export type ThemePreference = "system" | "light" | "dark";

const PREF_KEY = "nb-theme-pref";
const SYSTEM_KEY = "nb-system-dark";

const isPreference = (v: unknown): v is ThemePreference =>
    v === "system" || v === "light" || v === "dark";

const initialSystemDark = (): boolean => {
    try {
        const mirrored = localStorage.getItem(SYSTEM_KEY);
        if (mirrored !== null) return mirrored === "true";
    } catch {
        /* fall through */
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
};

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

    useEffect(() => {
        let cancelled = false;
        Preferences.Get()
            .then((prefs) => {
                if (!cancelled && isPreference(prefs?.theme)) setThemeState(prefs.theme);
            })
            .catch((err: unknown) => console.warn("[ThemeContext] load preferences failed", err));
        Theme.SystemDarkMode()
            .then((dark) => {
                if (!cancelled) setSystemDark(dark);
            })
            .catch((err: unknown) => console.warn("[ThemeContext] SystemDarkMode failed", err));

        // Cross-window sync: a flip in the settings window reaches every window.
        const offPrefs = Events.On("netbird:preferences:changed", (e: { data?: UIPreferences }) => {
            if (isPreference(e.data?.theme)) setThemeState(e.data.theme);
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

    // Apply the class and refresh the pre-paint mirror (index.html reads it).
    useEffect(() => {
        document.documentElement.classList.toggle("dark", resolvedDark);
        try {
            localStorage.setItem(PREF_KEY, theme);
            localStorage.setItem(SYSTEM_KEY, String(systemDark));
        } catch {
            /* mirror is best-effort */
        }
    }, [theme, systemDark, resolvedDark]);

    const setTheme = useCallback(async (next: ThemePreference) => {
        setThemeState(next);
        await Preferences.SetTheme(next as ThemePref);
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
