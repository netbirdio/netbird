import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Events } from "@wailsio/runtime";
import { Peers } from "@bindings/services";
import type { Status } from "@bindings/services/models.js";
import { DaemonUnavailableOverlay } from "@/components/empty-state/DaemonUnavailableOverlay.tsx";

const EVENT_STATUS = "netbird:status";

// StatusContext is the single subscription point for the daemon status
// stream. It owns the initial Peers.Get, the netbird:status event listener,
// and the synthetic DaemonUnavailable handling. The provider also renders
// the DaemonUnavailableOverlay so every layout that mounts it inherits the
// same blocker without re-importing the component.
//
// Boolean flags consumers should prefer over hand-rolled checks:
//   - isReady              first Peers.Get has resolved
//   - isDaemonUnavailable  ready and status === "DaemonUnavailable"
//   - isDaemonAvailable    ready and status !== "DaemonUnavailable"
type StatusContextValue = {
    status: Status | null;
    error: string | null;
    refresh: () => Promise<void>;
    isReady: boolean;
    isDaemonUnavailable: boolean;
    isDaemonAvailable: boolean;
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

    const refresh = useCallback(async () => {
        try {
            const s = await Peers.Get();
            setStatus(s);
            setError(null);
        } catch (e) {
            // Peers.Get returns a gRPC error when the socket itself is
            // unreachable (daemon not running, missing socket, etc.); only
            // the streaming path synthesizes a DaemonUnavailable status.
            // Synthesize one here too so the overlay paints on cold start
            // without a daemon — otherwise the whole UI stays blank since
            // `isReady` would never flip and StatusProvider's short-circuit
            // wouldn't render either children or the overlay.
            setStatus({ status: "DaemonUnavailable" } as Status);
            setError(String(e));
        }
    }, []);

    useEffect(() => {
        void refresh();
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

    // Don't mount children until the first Peers.Get has resolved and the
    // daemon is reachable. Consumers (ProfileContext, SettingsContext, …)
    // can then assume any daemon RPC they make at mount will reach the
    // socket — no per-context availability gating. When the daemon flips
    // back to unavailable the children unmount and remount fresh once it
    // returns.
    return (
        <StatusContext.Provider
            value={{
                status,
                error,
                refresh,
                isReady,
                isDaemonUnavailable,
                isDaemonAvailable,
            }}
        >
            {isDaemonAvailable && children}
            <DaemonUnavailableOverlay />
        </StatusContext.Provider>
    );
};
