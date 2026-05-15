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
import { Update as UpdateSvc } from "@bindings/services";
import type { State as UpdateState } from "@bindings/updater/models.js";
import { UpdateAvailableBanner } from "@/modules/auto-update/UpdateAvailableBanner";
import { UpdatingOverlay } from "@/modules/auto-update/UpdatingOverlay";

type ClientVersionContextValue = {
    updateAvailable: boolean;
    updateVersion: string | null;
    enforced: boolean;
    installing: boolean;
    triggerUpdate: () => void;
    updating: boolean;
    updateError: string | null;
    dismissUpdateError: () => void;
};

// Dev toggles — flip to preview UI states without triggering real flows.
const FORCE_UPDATE_AVAILABLE = false;
const FORCE_UPDATING = false;
const FORCE_ENFORCED = true;
const FORCE_VERSION = "0.65.0";
// Hide all "update available" UI (header trigger, settings badge, banner)
// regardless of what the daemon reports.
const HIDE_UPDATE_AVAILABLE = false;
// FORCE_ERROR options:
//   null       → no error (loading state)
//   "timeout"  → "Update timed out" state
//   "cancel"   → "Update canceled" state
//   "fail"     → generic "Update failed" state (uses FORCE_ERROR_MSG)
type ForceError = "timeout" | "cancel" | "fail" | null;
const FORCE_ERROR = null as ForceError;
const FORCE_ERROR_MSG = "installer exited with code 1";

const forcedErrorMessage = (): string | null => {
    switch (FORCE_ERROR) {
        case "timeout":
            return "update timed out after 15m";
        case "cancel":
            return "update canceled by user";
        case "fail":
            return FORCE_ERROR_MSG;
        default:
            return null;
    }
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
    const [updateError, setUpdateError] = useState<string | null>(null);

    // Pull the current state once on mount so a banner / overlay that
    // re-renders later in the session still has the right baseline, then
    // subscribe to the push channel for live updates.
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

    // Merge the live state with dev overrides. The overrides win so designers
    // can preview any branch without involving the daemon.
    const effective = useMemo<UpdateState>(() => {
        if (HIDE_UPDATE_AVAILABLE) return emptyState;
        if (FORCE_UPDATE_AVAILABLE || FORCE_UPDATING) {
            return {
                available: true,
                version: FORCE_VERSION,
                enforced: FORCE_ENFORCED,
                installing: FORCE_UPDATING,
            };
        }
        return state;
    }, [state]);

    const triggerUpdate = useCallback(() => {
        setUpdateError(null);
        setUpdating(true);
        UpdateSvc.Trigger()
            .then((result) => {
                if (!result?.success) {
                    setUpdateError(result?.errorMsg || "Update failed");
                    setUpdating(false);
                }
            })
            .catch((e: unknown) => {
                setUpdateError(String(e));
                setUpdating(false);
            });
    }, []);

    const dismissUpdateError = useCallback(() => setUpdateError(null), []);

    const showOverlay = updating || effective.installing || updateError || FORCE_ERROR;

    const value = useMemo<ClientVersionContextValue>(
        () => ({
            updateAvailable: effective.available,
            updateVersion: effective.version || null,
            enforced: effective.enforced,
            installing: effective.installing,
            triggerUpdate,
            updating,
            updateError,
            dismissUpdateError,
        }),
        [effective, triggerUpdate, updating, updateError, dismissUpdateError],
    );

    return (
        <ClientVersionContext.Provider value={value}>
            {children}
            <UpdateAvailableBanner />
            {showOverlay && (
                <UpdatingOverlay
                    version={effective.version || null}
                    error={updateError ?? forcedErrorMessage()}
                    onDismiss={dismissUpdateError}
                />
            )}
        </ClientVersionContext.Provider>
    );
};
