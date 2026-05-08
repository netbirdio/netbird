import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { Settings as SettingsSvc } from "@bindings/services";
import type { Config } from "@bindings/services/models.js";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";

const SAVE_DEBOUNCE_MS = 400;

type SettingsContextValue = {
    config: Config;
    setField: <K extends keyof Config>(k: K, v: Config[K]) => void;
    saveField: <K extends keyof Config>(k: K, v: Config[K]) => Promise<void>;
    saveFields: (partial: Partial<Config>) => Promise<void>;
    saveNow: () => Promise<void>;
};

const SettingsContext = createContext<SettingsContextValue | null>(null);

export const useSettings = () => {
    const ctx = useContext(SettingsContext);
    if (!ctx) {
        throw new Error("useSettings must be used inside SettingsProvider");
    }
    return ctx;
};

const useSettingsState = () => {
    const { username, activeProfile, loaded: profileLoaded } = useProfile();
    const [config, setConfig] = useState<Config | null>(null);
    const [error, setError] = useState<string | null>(null);
    const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    useEffect(() => {
        if (!profileLoaded || !activeProfile) return;
        (async () => {
            try {
                const c = await SettingsSvc.GetConfig({
                    profileName: activeProfile,
                    username,
                });
                setConfig(c);
                setError(null);
            } catch (e) {
                setError(String(e));
            }
        })();
    }, [profileLoaded, activeProfile, username]);

    useEffect(
        () => () => {
            if (saveTimer.current) clearTimeout(saveTimer.current);
        },
        [],
    );

    const save = useCallback(
        async (next: Config) => {
            try {
                await SettingsSvc.SetConfig({
                    ...next,
                    profileName: activeProfile,
                    username,
                });
                setError(null);
            } catch (e) {
                setError(String(e));
            }
        },
        [activeProfile, username],
    );

    const setField = useCallback(
        <K extends keyof Config>(k: K, v: Config[K]) => {
            setConfig((c) => {
                if (!c) return c;
                const next = { ...c, [k]: v };
                if (saveTimer.current) clearTimeout(saveTimer.current);
                saveTimer.current = setTimeout(() => {
                    void save(next);
                }, SAVE_DEBOUNCE_MS);
                return next;
            });
        },
        [save],
    );

    const saveNow = useCallback(async () => {
        if (!config) return;
        if (saveTimer.current) {
            clearTimeout(saveTimer.current);
            saveTimer.current = null;
        }
        await save(config);
    }, [config, save]);

    const saveField = useCallback(
        async <K extends keyof Config>(k: K, v: Config[K]) => {
            if (!config) return;
            if (saveTimer.current) {
                clearTimeout(saveTimer.current);
                saveTimer.current = null;
            }
            const next = { ...config, [k]: v };
            setConfig(next);
            await save(next);
        },
        [config, save],
    );

    const saveFields = useCallback(
        async (partial: Partial<Config>) => {
            if (!config) return;
            if (saveTimer.current) {
                clearTimeout(saveTimer.current);
                saveTimer.current = null;
            }
            const next = { ...config, ...partial };
            setConfig(next);
            await save(next);
        },
        [config, save],
    );

    return { config, error, setField, saveField, saveFields, saveNow };
};

export const SettingsProvider = ({ children }: { children: ReactNode }) => {
    const { config, error, setField, saveField, saveFields, saveNow } =
        useSettingsState();

    return (
        <>
            {error && <p className={"pb-6 text-sm text-red-500"}>{error}</p>}
            <div className={"flex-1 min-h-0 overflow-y-auto"}>
                {!config ? (
                    <div className={"p-6 text-sm text-nb-gray-500"}>Loading…</div>
                ) : (
                    <SettingsContext.Provider
                        value={{
                            config,
                            setField,
                            saveField,
                            saveFields,
                            saveNow,
                        }}
                    >
                        {children}
                    </SettingsContext.Provider>
                )}
            </div>
        </>
    );
};
