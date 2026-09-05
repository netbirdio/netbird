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
import { Autostart, Settings as SettingsSvc, Version } from "@bindings/services";
import type { Config } from "@bindings/services/models.js";
import i18next from "@/lib/i18n";
import { useProfile } from "@/contexts/ProfileContext.tsx";
import { SettingsSkeleton } from "@/modules/settings/SettingsSkeleton.tsx";
import { errorCommand, errorDialog, formatErrorMessage as errorMessage } from "@/lib/errors.ts";

const SAVE_DEBOUNCE_MS = 400;

const logSaveError = (err: unknown) => console.error("[SettingsContext] save failed", err);

export type AutostartState = { supported: boolean; enabled: boolean };

// GuardedField is a setting the daemon only accepts from root/administrator.
// Turning one on goes through saveGuardedField, which asks the operating system
// for the privileges rather than sending a request that would be refused.
export type GuardedField =
    | "serverSshAllowed"
    | "enableSshRoot"
    | "disableSshAuth"
    | "serverVncAllowed"
    | "disableVncApproval";

type SettingsContextValue = {
    config: Config;
    guiVersion: string;
    setField: <K extends keyof Config>(k: K, v: Config[K]) => void;
    saveField: <K extends keyof Config>(k: K, v: Config[K]) => Promise<void>;
    saveFields: (partial: Partial<Config>, opts?: { preSharedKey?: string }) => Promise<void>;
    saveGuardedField: (k: GuardedField, v: boolean) => Promise<void>;
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
        throw new Error("useAutostartSetting must be used inside AutostartSettingsProvider");
    }
    return ctx;
};

type LoadedConfig = { profileName: string; data: Config };

const useSettingsState = () => {
    const { username, activeProfileId, loaded: profileLoaded } = useProfile();
    const [loaded, setLoaded] = useState<LoadedConfig | null>(null);
    const [guiVersion, setGuiVersion] = useState<string>("—");
    const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    const loadedRef = useRef<LoadedConfig | null>(null);
    // Set when the daemon's config changed while a save was pending, so the read
    // that was skipped to protect the pending edit happens once it is through.
    // Without it the form keeps values the daemon no longer has and the next save
    // submits them, which for a guarded setting means asking the user to authorize
    // a change they never made.
    const reloadOwed = useRef(false);

    useEffect(() => {
        loadedRef.current = loaded;
    }, [loaded]);

    // reload re-reads the daemon's config, which is authoritative. Used on
    // mount, on the daemon's config_changed event, and to undo an optimistic
    // update the daemon then rejected.
    const reload = useCallback(
        async (profileName: string) => {
            reloadOwed.current = false;
            try {
                const data = await SettingsSvc.GetConfig({ profileName, username });
                setLoaded({ profileName, data });
            } catch (e) {
                console.warn("[SettingsContext] reload after rejected save failed", e);
            }
        },
        [username],
    );

    useEffect(() => {
        if (!profileLoaded || !activeProfileId) return;
        let cancelled = false;

        const load = async (showError: boolean) => {
            try {
                const data = await SettingsSvc.GetConfig({
                    profileName: activeProfileId,
                    username,
                });
                if (cancelled) return;
                // A pending edit outranks the daemon's copy until it is saved, so
                // the read is owed rather than dropped: see reloadOwed.
                if (saveTimer.current) {
                    reloadOwed.current = true;
                    return;
                }
                setLoaded({ profileName: activeProfileId, data });
            } catch (e) {
                if (cancelled || !showError) return;
                await errorDialog({
                    Title: i18next.t("settings.error.loadTitle"),
                    Message: errorMessage(e),
                });
            }
        };

        load(true);

        const off = Events.On(
            "netbird:event",
            (e: { data?: { metadata?: { [k: string]: string | undefined } } }) => {
                if (e.data?.metadata?.type === "config_changed") load(false);
            },
        );

        return () => {
            cancelled = true;
            off();
        };
    }, [profileLoaded, activeProfileId, username]);

    useEffect(() => {
        let cancelled = false;
        Version.GUI().then((v) => {
            if (!cancelled) setGuiVersion(v);
        });
        return () => {
            cancelled = true;
        };
    }, []);

    useEffect(
        () => () => {
            if (saveTimer.current) clearTimeout(saveTimer.current);
        },
        [],
    );

    const save = useCallback(
        async (profileName: string, next: Config, preSharedKey?: string) => {
            const preSharedKeyWrite = preSharedKey === undefined ? {} : { preSharedKey };
            try {
                const { declined } = await SettingsSvc.SetConfig({
                    ...next,
                    ...preSharedKeyWrite,
                    profileName,
                    username,
                });
                // The change needed authorization and the user said no, so the
                // optimistic update is wrong. Nothing to report: they know.
                if (declined || reloadOwed.current) {
                    await reload(profileName);
                }
            } catch (e) {
                // The optimistic update is wrong now: the daemon refused it
                // (a change that needs elevated privileges, an MDM-managed
                // field, ...). Snap the controls back to what it actually
                // holds before reporting, so the UI never shows a value the
                // daemon does not have.
                await reload(profileName);
                await errorDialog({
                    Title: i18next.t("settings.error.saveTitle"),
                    Message: errorMessage(e),
                    Command: errorCommand(e),
                });
            }
        },
        [username, reload],
    );

    const setField = useCallback(
        <K extends keyof Config>(k: K, v: Config[K]) => {
            const cur = loadedRef.current;
            if (!cur) return;
            const next: LoadedConfig = {
                profileName: cur.profileName,
                data: { ...cur.data, [k]: v },
            };
            loadedRef.current = next;
            setLoaded(next);
            if (saveTimer.current) clearTimeout(saveTimer.current);
            saveTimer.current = setTimeout(() => {
                saveTimer.current = null;
                save(next.profileName, next.data).catch(logSaveError);
            }, SAVE_DEBOUNCE_MS);
        },
        [save],
    );

    const saveNow = useCallback(async () => {
        if (!loaded) return;
        if (saveTimer.current) {
            clearTimeout(saveTimer.current);
            saveTimer.current = null;
        }
        await save(loaded.profileName, loaded.data);
    }, [loaded, save]);

    const saveField = useCallback(
        async <K extends keyof Config>(k: K, v: Config[K]) => {
            if (!loaded) return;
            if (saveTimer.current) {
                clearTimeout(saveTimer.current);
                saveTimer.current = null;
            }
            const next = { ...loaded.data, [k]: v };
            setLoaded({ profileName: loaded.profileName, data: next });
            await save(loaded.profileName, next);
        },
        [loaded, save],
    );

    // saveGuardedField applies a setting the daemon restricts to
    // root/administrator by having the Go side run the app again under the
    // platform's elevation prompt (UAC, the macOS authentication dialog, polkit).
    // The prompt is the user's, so the call is made straight from their gesture
    // and never from the debounce.
    const saveGuardedField = useCallback(
        async (k: GuardedField, v: boolean) => {
            const cur = loadedRef.current;
            if (!cur) return;

            // Flush what the debounce still owes, before the optimistic update
            // below joins it: a later save carrying the guarded value would be
            // refused, and its error dialog would be the second one for a change
            // the user already authorized.
            if (saveTimer.current) {
                clearTimeout(saveTimer.current);
                saveTimer.current = null;
                await save(cur.profileName, cur.data);
            }

            const next: LoadedConfig = {
                profileName: cur.profileName,
                data: { ...cur.data, [k]: v },
            };
            loadedRef.current = next;
            setLoaded(next);

            try {
                await SettingsSvc.SetGuardedSettings({
                    profileName: cur.profileName,
                    username,
                    [k]: v,
                });
            } catch (e) {
                // The daemon is authoritative either way, so re-read before
                // reporting. A declined prompt is not an error and does not come
                // through here at all; this is a prompt that could not be raised,
                // which carries the command that would have done it.
                await reload(cur.profileName);
                await errorDialog({
                    Title: i18next.t("settings.error.saveTitle"),
                    Message: errorMessage(e),
                    Command: errorCommand(e),
                });
                return;
            }
            // Either the change went through or the user declined it. The daemon
            // says which.
            await reload(cur.profileName);
        },
        [username, save, reload],
    );

    const saveFields = useCallback(
        async (partial: Partial<Config>, opts?: { preSharedKey?: string }) => {
            if (!loaded) return;
            if (saveTimer.current) {
                clearTimeout(saveTimer.current);
                saveTimer.current = null;
            }

            const merged: Config = { ...loaded.data, ...partial };
            const next: Config =
                opts?.preSharedKey === undefined
                    ? merged
                    : { ...merged, preSharedKeySet: opts.preSharedKey !== "" };
            setLoaded({ profileName: loaded.profileName, data: next });
            await save(loaded.profileName, next, opts?.preSharedKey);
        },
        [loaded, save],
    );

    return {
        config: loaded?.data ?? null,
        guiVersion,
        setField,
        saveField,
        saveFields,
        saveGuardedField,
        saveNow,
    };
};

export const SettingsProvider = ({ children }: { children: ReactNode }) => {
    const { config, guiVersion, setField, saveField, saveFields, saveGuardedField, saveNow } =
        useSettingsState();

    const value = useMemo<SettingsContextValue | null>(
        () =>
            config
                ? { config, guiVersion, setField, saveField, saveFields, saveGuardedField, saveNow }
                : null,
        [config, guiVersion, setField, saveField, saveFields, saveGuardedField, saveNow],
    );

    if (!value) {
        return (
            <div className={"min-h-0 flex-1 overflow-y-auto px-7 py-8"}>
                <SettingsSkeleton />
            </div>
        );
    }

    return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
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
        })().catch((err: unknown) => {
            if (cancelled) return;
            console.warn("[SettingsContext] load autostart state failed", err);
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

    const value = useMemo<AutostartContextValue>(
        () => ({ autostart, setAutostartEnabled }),
        [autostart, setAutostartEnabled],
    );

    return <AutostartContext.Provider value={value}>{children}</AutostartContext.Provider>;
};
