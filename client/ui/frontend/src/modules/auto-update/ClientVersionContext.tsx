import { createContext, useContext, useMemo, type ReactNode } from "react";
import { Update as UpdateSvc } from "@bindings/services";
import { useStatus } from "@/hooks/useStatus";
import { UpdateAvailableBanner } from "@/modules/auto-update/UpdateAvailableBanner";

type ClientVersionContextValue = {
    updateAvailable: boolean;
    updateVersion: string | null;
    triggerUpdate: () => void;
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

    const value = useMemo<ClientVersionContextValue>(() => {
        const version = (status?.events ?? [])
            .map((e) => e.metadata?.["new_version_available"])
            .find((v): v is string => Boolean(v));

        return {
            updateAvailable: Boolean(version),
            updateVersion: version ?? null,
            triggerUpdate: () => {
                UpdateSvc.Trigger().catch(() => {});
            },
        };
    }, [status]);

    return (
        <ClientVersionContext.Provider value={value}>
            {children}
            <UpdateAvailableBanner />
        </ClientVersionContext.Provider>
    );
};
