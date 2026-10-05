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
import i18next from "@/lib/i18n";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

const isDaemonUnavailable = (e: unknown): boolean => {
    const msg = e instanceof Error ? e.message : String(e);
    return msg.includes("code = Unavailable");
};

type ClientVersionContextValue = {
    updateAvailable: boolean;
    updateVersion: string | null;
    enforced: boolean;
    installing: boolean;
    triggerUpdate: () => void;
    updating: boolean;
};

const EVENT_UPDATE_STATE = "netbird:update:state";

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

    useEffect(() => {
        let cancelled = false;
        UpdateSvc.GetState()
            .then((s) => {
                if (cancelled || !s) return;
                setState(s);
            })
            .catch((e) => {
                if (cancelled || isDaemonUnavailable(e)) return;
                void errorDialog({
                    Title: i18next.t("update.error.loadStateTitle"),
                    Message: formatErrorMessage(e),
                });
            });
        const off = Events.On(EVENT_UPDATE_STATE, (ev: { data: UpdateState }) => {
            if (ev?.data) setState(ev.data);
        });
        return () => {
            cancelled = true;
            off?.();
        };
    }, []);

    const prevInstallingRef = useRef(false);
    useEffect(() => {
        if (state.installing && !prevInstallingRef.current) {
            WindowManager.OpenInstallProgress(state.version || "").catch(console.error);
        }
        prevInstallingRef.current = state.installing;
    }, [state.installing, state.version]);

    const triggerUpdate = useCallback(() => {
        setUpdating(true);
        WindowManager.OpenInstallProgress(state.version || "").catch(console.error);
        UpdateSvc.Trigger()
            .catch(async (e) => {
                if (isDaemonUnavailable(e)) return;
                WindowManager.CloseInstallProgress().catch(console.error);
                await errorDialog({
                    Title: i18next.t("update.error.triggerTitle"),
                    Message: formatErrorMessage(e),
                });
            })
            .finally(() => setUpdating(false));
    }, [state.version]);

    const value = useMemo<ClientVersionContextValue>(
        () => ({
            updateAvailable: state.available,
            updateVersion: state.version || null,
            enforced: state.enforced,
            installing: state.installing,
            triggerUpdate,
            updating,
        }),
        [state, triggerUpdate, updating],
    );

    return <ClientVersionContext.Provider value={value}>{children}</ClientVersionContext.Provider>;
};
