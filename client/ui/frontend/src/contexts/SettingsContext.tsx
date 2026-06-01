import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { errorDialog } from "@/lib/dialogs.ts";
import { Autostart, Settings as SettingsSvc } from "@bindings/services";
import type { Config } from "@bindings/services/models.js";
import i18next from "@/lib/i18n";
import { useProfile } from "@/contexts/ProfileContext.tsx";
import { SettingsSkeleton } from "@/modules/settings/SettingsSkeleton.tsx";
import { formatErrorMessage as errorMessage } from "@/lib/errors.ts";

const SAVE_DEBOUNCE_MS = 400;

export type AutostartState = { supported: boolean; enabled: boolean };

type SettingsContextValue = {
    config: Config;
    setField: <K extends keyof Config>(k: K, v: Config[K]) => void;
    saveField: <K extends keyof Config>(k: K, v: Config[K]) => Promise<void>;
    saveFields: (partial: Partial<Config>) => Promise<void>;
    saveNow: () => Promise<void>;
};

type AutostartContextValue = {
    autostart: AutostartState | null;
    setAutostartEnabled: (enabled: boolean) => Promise<void>;
};

const SettingsContext = createContext<SettingsContextValue | null>(null);
const AutostartContext = createContext<AutostartContextValue | null>(null);

export const useSettings = () => {
    const ctx = useContext(SettingsContext);
    if (!ctx) {
        throw new Error("useSettings must be used inside SettingsProvider");
    }
    return ctx;
};

export const useAutostartSetting = () => {
    const ctx = useContext(AutostartContext);
    if (!ctx) {
        throw new Error(
            "useAutostartSetting must be used inside AutostartSettingsProvider",
        );
    }
    return ctx;
};

const useSettingsState = () => {
    const { username, activeProfile, loaded: profileLoaded } = useProfile();
    const [config, setConfig] = useState<Config | null>(null);
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
            } catch (e) {
                await errorDialog({
                    Title: i18next.t("settings.error.loadTitle"),
                    Message: errorMessage(e),
                });
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
            // The daemon masks an existing PSK as "**********" in GetConfig.
            // Sending the mask back round-trips it into the saved config and
            // wgtypes.ParseKey fails on the next connect. Drop the mask so
            // unrelated toggles don't corrupt the stored PSK.
            const { preSharedKey, ...rest } = next;
            try {
                await SettingsSvc.SetConfig({
                    ...rest,
                    ...(preSharedKey === "**********" ? {} : { preSharedKey }),
                    profileName: activeProfile,
                    username,
                });
            } catch (e) {
                await errorDialog({
                    Title: i18next.t("settings.error.saveTitle"),
                    Message: errorMessage(e),
                });
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

    return { config, setField, saveField, saveFields, saveNow };
};

export const SettingsProvider = ({ children }: { children: ReactNode }) => {
    const { config, setField, saveField, saveFields, saveNow } = useSettingsState();

    return (
        <div className={"flex-1 min-h-0 overflow-y-auto"}>
            {!config ? (
                <SettingsSkeleton />
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
    );
};

export const AutostartSettingsProvider = ({ children }: { children: ReactNode }) => {
    const [autostart, setAutostart] = useState<AutostartState | null>(null);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            const supported = await Autostart.Supported();
            const enabled = supported ? await Autostart.IsEnabled() : false;
            if (cancelled) return;
            setAutostart({ supported, enabled });
        })().catch(() => {
            if (cancelled) return;
            setAutostart({ supported: false, enabled: false });
        });
        return () => {
            cancelled = true;
        };
    }, []);

    const setAutostartEnabled = useCallback(async (enabled: boolean) => {
        setAutostart((s) => (s ? { ...s, enabled } : s));
        try {
            await Autostart.SetEnabled(enabled);
        } catch (e) {
            setAutostart((s) => (s ? { ...s, enabled: !enabled } : s));
            await errorDialog({
                Title: i18next.t("settings.general.autostart.errorTitle"),
                Message: errorMessage(e),
            });
        }
    }, []);

    return (
        <AutostartContext.Provider value={{ autostart, setAutostartEnabled }}>
            {children}
        </AutostartContext.Provider>
    );
};
