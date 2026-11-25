import { useCallback, useEffect, useRef, useState } from "react";
import { AgentNetwork as AgentNetworkSvc } from "@bindings/services";
import type { AgentNetworkInfo } from "@bindings/services/models.js";
import { formatErrorMessage } from "@/lib/errors";

export const AGENT_NETWORK_POLL_MS = 60_000;

// States in which Agent Networks has nothing to show this user, so the tab stays hidden.
const HIDDEN_STATES = new Set(["not_enabled", "management_unsupported"]);

export const isAgentNetworkAvailable = (info: AgentNetworkInfo | null): boolean =>
    info !== null && !HIDDEN_STATES.has(info.state);

type Options = {
    enabled: boolean;
    // Refetch interval while the window is visible; omit to fetch once.
    pollMs?: number;
};

export const useAgentNetworkInfo = ({ enabled, pollMs }: Options) => {
    const [info, setInfo] = useState<AgentNetworkInfo | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    // Bumped by refresh() to rerun the fetch effect on demand.
    const [refreshTick, setRefreshTick] = useState(0);
    const refresh = useCallback(() => setRefreshTick((n) => n + 1), []);
    // Only the latest request may update state; an older one can resolve last.
    const latest = useRef(0);

    const load = useCallback(async (cancelled: () => boolean) => {
        const id = ++latest.current;
        const isCancelled = () => cancelled() || id !== latest.current;
        setLoading(true);
        try {
            const next = await AgentNetworkSvc.Info();
            if (isCancelled()) return;
            setInfo(next);
            setError(null);
        } catch (e: unknown) {
            if (!isCancelled()) setError(formatErrorMessage(e));
        } finally {
            if (!isCancelled()) setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (!enabled) {
            // Drop the previous connection's answer; it may belong to another profile.
            setInfo(null);
            setError(null);
            setLoading(false);
            return;
        }
        let cancelled = false;
        const isCancelled = () => cancelled;
        void load(isCancelled);
        if (!pollMs) {
            return () => {
                cancelled = true;
            };
        }

        const refreshIfVisible = () => {
            if (document.visibilityState === "visible") void load(isCancelled);
        };
        const timer = setInterval(refreshIfVisible, pollMs);
        document.addEventListener("visibilitychange", refreshIfVisible);
        return () => {
            cancelled = true;
            clearInterval(timer);
            document.removeEventListener("visibilitychange", refreshIfVisible);
        };
    }, [enabled, pollMs, load, refreshTick]);

    return { info, error, loading, refresh };
};
