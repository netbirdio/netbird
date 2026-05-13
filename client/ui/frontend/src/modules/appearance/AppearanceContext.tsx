import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useState,
    type ReactNode,
} from "react";

export type AppearanceView = "default" | "advanced";
export type ConnectionLayout = "default" | "switch";

export type AppearanceState = {
    view: AppearanceView;
    connectionLayout: ConnectionLayout;
    expanded: boolean;
    showPeersNav: boolean;
    showResourcesNav: boolean;
    showExitNodeNav: boolean;
    showProfileSelector: boolean;
    showSettingsButton: boolean;
};

const STORAGE_KEY = "netbird:appearance";

const DEFAULTS: AppearanceState = {
    view: "default",
    connectionLayout: "default",
    expanded: true,
    showPeersNav: true,
    showResourcesNav: true,
    showExitNodeNav: true,
    showProfileSelector: true,
    showSettingsButton: true,
};

const readStored = (): AppearanceState => {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return DEFAULTS;
        const parsed = JSON.parse(raw) as Partial<AppearanceState>;
        return { ...DEFAULTS, ...parsed };
    } catch {
        return DEFAULTS;
    }
};

type AppearanceContextValue = AppearanceState & {
    setView: (v: AppearanceView) => void;
    setField: <K extends keyof AppearanceState>(k: K, v: AppearanceState[K]) => void;
};

const AppearanceContext = createContext<AppearanceContextValue | null>(null);

export const useAppearance = () => {
    const ctx = useContext(AppearanceContext);
    if (!ctx) {
        throw new Error("useAppearance must be used inside AppearanceProvider");
    }
    return ctx;
};

export const AppearanceProvider = ({ children }: { children: ReactNode }) => {
    const [state, setState] = useState<AppearanceState>(() => readStored());

    useEffect(() => {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
        } catch {
            // ignore quota / unavailable storage
        }
    }, [state]);

    const setField = useCallback(
        <K extends keyof AppearanceState>(k: K, v: AppearanceState[K]) => {
            setState((s) => ({ ...s, [k]: v }));
        },
        [],
    );

    const setView = useCallback((v: AppearanceView) => {
        setState((s) => ({ ...s, view: v }));
    }, []);

    const value = useMemo<AppearanceContextValue>(
        () => ({ ...state, setView, setField }),
        [state, setView, setField],
    );

    return (
        <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>
    );
};
