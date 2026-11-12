import { useCallback, useEffect, useState } from "react";
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
    // Counts successful fetches, so dependents can refresh along with the info.
    const [fetchCount, setFetchCount] = useState(0);

    const load = useCallback(async (isCancelled: () => boolean) => {
        setLoading(true);
        try {
            const next = await AgentNetworkSvc.Info();
            if (isCancelled()) return;
            setInfo(next);
            setFetchCount((n) => n + 1);
            setError(null);
        } catch (e: unknown) {
            if (!isCancelled()) setError(formatErrorMessage(e));
        } finally {
            if (!isCancelled()) setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (!enabled) return;
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
    }, [enabled, pollMs, load]);

    return { info, error, loading, fetchCount };
};
