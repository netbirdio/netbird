import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { Update as UpdateSvc } from "@bindings/services";
import { useStatus } from "@/hooks/useStatus";
import { UpdateAvailableBanner } from "@/modules/auto-update/UpdateAvailableBanner";
import { UpdatingOverlay } from "@/modules/auto-update/UpdatingOverlay";

type ClientVersionContextValue = {
    updateAvailable: boolean;
    updateVersion: string | null;
    triggerUpdate: () => void;
    updating: boolean;
    updateError: string | null;
    dismissUpdateError: () => void;
};

// Dev toggles — flip to preview UI states without triggering real flows.
const FORCE_UPDATE_AVAILABLE = true;
const FORCE_UPDATING = false;
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

const ClientVersionContext = createContext<ClientVersionContextValue | null>(null);

export const useClientVersion = () => {
    const ctx = useContext(ClientVersionContext);
    if (!ctx) {
        throw new Error("useClientVersion must be used inside ClientVersionProvider");
    }
    return ctx;
};

export const ClientVersionProvider = ({ children }: { children: ReactNode }) => {
    const { status } = useStatus();
    const [updating, setUpdating] = useState(false);
    const [updateError, setUpdateError] = useState<string | null>(null);

    const updateVersion = useMemo(() => {
        if (HIDE_UPDATE_AVAILABLE) return null;
        if (FORCE_UPDATE_AVAILABLE || FORCE_UPDATING) return FORCE_VERSION;
        return (
            (status?.events ?? [])
                .map((e) => e.metadata?.["new_version_available"])
                .find((v): v is string => Boolean(v)) ?? null
        );
    }, [status]);

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

    const value = useMemo<ClientVersionContextValue>(
        () => ({
            updateAvailable: Boolean(updateVersion),
            updateVersion,
            triggerUpdate,
            updating,
            updateError,
            dismissUpdateError,
        }),
        [updateVersion, triggerUpdate, updating, updateError, dismissUpdateError],
    );

    return (
        <ClientVersionContext.Provider value={value}>
            {children}
            <UpdateAvailableBanner />
            {(updating || updateError || FORCE_UPDATING || FORCE_ERROR) && (
                <UpdatingOverlay
                    version={updateVersion}
                    error={updateError ?? forcedErrorMessage()}
                    onDismiss={dismissUpdateError}
                />
            )}
        </ClientVersionContext.Provider>
    );
};
