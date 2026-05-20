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
import { Update as UpdateSvc, WindowManager } from "@bindings/services";
import type { State as UpdateState } from "@bindings/updater/models.js";

type ClientVersionContextValue = {
    updateAvailable: boolean;
    updateVersion: string | null;
    enforced: boolean;
    installing: boolean;
    triggerUpdate: () => void;
    updating: boolean;
};

const EVENT_UPDATE_STATE = "netbird:update:state";

// Dev tab in Settings emits this with { updateAvailable, enforced, version }.
// Lives only in-memory in the main window for the session — losing it when
// Settings closes is acceptable per the dev-toggle scope (no daemon write,
// no persistence). See SettingsDevelopment.tsx.
const EVENT_DEV_OVERRIDES = "netbird:dev:overrides";

type DevOverrides = {
    updateAvailable: boolean;
    enforced: boolean;
    version: string;
};

const emptyState: UpdateState = {
    available: false,
    version: "",
    enforced: false,
    installing: false,
};

const ClientVersionContext = createContext<ClientVersionContextValue | null>(null);

export const useClientVersion = () => {
    const ctx = useContext(ClientVersionContext);
    if (!ctx) {
        throw new Error("useClientVersion must be used inside ClientVersionProvider");
    }
    return ctx;
};

export const ClientVersionProvider = ({ children }: { children: ReactNode }) => {
    const [state, setState] = useState<UpdateState>(emptyState);
    const [updating, setUpdating] = useState(false);
    const [devOverride, setDevOverride] = useState<DevOverrides | null>(null);

    useEffect(() => {
        let cancelled = false;
        UpdateSvc.GetState()
            .then((s) => {
                if (cancelled || !s) return;
                setState(s);
            })
            .catch(() => {
                /* daemon unreachable — leave defaults */
            });
        const off = Events.On(EVENT_UPDATE_STATE, (ev: { data: UpdateState }) => {
            if (ev?.data) setState(ev.data);
        });
        return () => {
            cancelled = true;
            off?.();
        };
    }, []);

    useEffect(() => {
        const off = Events.On(EVENT_DEV_OVERRIDES, (ev: { data: DevOverrides }) => {
            if (ev?.data) setDevOverride(ev.data);
        });
        return () => {
            off?.();
        };
    }, []);

    // Dev override only kicks in when it explicitly forces updateAvailable on.
    // Otherwise daemon truth wins.
    const effective = useMemo<UpdateState>(() => {
        if (devOverride && devOverride.updateAvailable) {
            return {
                available: true,
                version: devOverride.version || "0.65.0",
                enforced: devOverride.enforced,
                installing: state.installing,
            };
        }
        return state;
    }, [state, devOverride]);

    // Force-install branch: daemon's progress_window:show flipped installing
    // to true while the UI was idle. Open the install window so the user
    // sees the progress UI without having to click anything.
    const prevInstallingRef = useRef(false);
    useEffect(() => {
        if (effective.installing && !prevInstallingRef.current) {
            WindowManager.OpenInstallProgress(effective.version || "").catch(console.error);
        }
        prevInstallingRef.current = effective.installing;
    }, [effective.installing, effective.version]);

    // Enforced user-driven branch: kick Trigger() in the background, then
    // hand off to the install window. The window owns the polling loop and
    // the final Quit() — this provider just fires the trigger.
    const triggerUpdate = useCallback(() => {
        setUpdating(true);
        WindowManager.OpenInstallProgress(effective.version || "").catch(console.error);
        UpdateSvc.Trigger()
            .catch(() => {
                // The daemon may already be down (force-install branch raced
                // us). The install window's polling loop handles it.
            })
            .finally(() => setUpdating(false));
    }, [effective.version]);

    const value = useMemo<ClientVersionContextValue>(
        () => ({
            updateAvailable: effective.available,
            updateVersion: effective.version || null,
            enforced: effective.enforced,
            installing: effective.installing,
            triggerUpdate,
            updating,
        }),
        [effective, triggerUpdate, updating],
    );

    return (
        <ClientVersionContext.Provider value={value}>
            {children}
        </ClientVersionContext.Provider>
    );
};
