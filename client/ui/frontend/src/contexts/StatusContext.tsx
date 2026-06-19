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
import { DaemonFeed } from "@bindings/services";
import { Status } from "@bindings/services/models.js";
import { DaemonOutdatedOverlay } from "@/components/empty-state/DaemonOutdatedOverlay.tsx";
import { DaemonUnavailableOverlay } from "@/components/empty-state/DaemonUnavailableOverlay.tsx";
import { isDaemonCompatible } from "@/lib/compat";

const EVENT_STATUS = "netbird:status";

type StatusContextValue = {
    status: Status | null;
    error: string | null;
    refresh: () => Promise<void>;
    isReady: boolean;
    isDaemonUnavailable: boolean;
    isDaemonAvailable: boolean;
    isDaemonOutdated: boolean;
};

const StatusContext = createContext<StatusContextValue | null>(null);

export const useStatus = () => {
    const ctx = useContext(StatusContext);
    if (!ctx) {
        throw new Error("useStatus must be used inside StatusProvider");
    }
    return ctx;
};

export const StatusProvider = ({ children }: { children: ReactNode }) => {
    const [status, setStatus] = useState<Status | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [isDaemonOutdated, setIsDaemonOutdated] = useState(false);

    const refresh = useCallback(async () => {
        try {
            const s = await DaemonFeed.Get();
            setStatus(s);
            setError(null);
        } catch (e) {
            // Synthesize DaemonUnavailable so cold-start-without-daemon isn't a blank UI (isReady stays false otherwise).
            setStatus(Status.createFrom({ status: "DaemonUnavailable" }));
            setError(String(e));
        }
    }, []);

    useEffect(() => {
        refresh().catch((err: unknown) => console.error("[StatusContext] refresh failed", err));
        const off = Events.On(EVENT_STATUS, (ev: { data: Status }) => {
            setStatus(ev.data);
            setError(null);
        });
        return () => {
            off();
        };
    }, [refresh]);

    const isReady = status !== null;
    const isDaemonUnavailable = isReady && status.status === "DaemonUnavailable";
    const isDaemonAvailable = isReady && !isDaemonUnavailable;

    useEffect(() => {
        if (!isDaemonAvailable) return;
        let cancelled = false;
        isDaemonCompatible()
            .then((ok) => {
                if (!cancelled) setIsDaemonOutdated(!ok);
            })
            .catch((err) => {
                console.error("[StatusContext] daemon compatible error", err);
            });
        return () => {
            cancelled = true;
        };
    }, [isDaemonAvailable]);

    const value = useMemo<StatusContextValue>(
        () => ({
            status,
            error,
            refresh,
            isReady,
            isDaemonUnavailable,
            isDaemonAvailable,
            isDaemonOutdated,
        }),
        [status, error, refresh, isReady, isDaemonUnavailable, isDaemonAvailable, isDaemonOutdated],
    );

    return (
        <StatusContext.Provider value={value}>
            {isDaemonAvailable && !isDaemonOutdated && children}
            <DaemonUnavailableOverlay />
            <DaemonOutdatedOverlay />
        </StatusContext.Provider>
    );
};
