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
import { Networks as NetworksSvc } from "@bindings/services";
import type { Network } from "@bindings/services/models.js";
import { useStatus } from "@/contexts/StatusContext";

// A route that covers all traffic (0.0.0.0/0 or ::/0) is an exit node.
// The daemon may merge a v4+v6 pair into a single comma-joined range string.
export const isExitNode = (range: string): boolean =>
    range.split(",").some((part) => {
        const trimmed = part.trim();
        return trimmed === "0.0.0.0/0" || trimmed === "::/0";
    });

type NetworksContextValue = {
    routes: Network[];
    networkRoutes: Network[];
    exitNodes: Network[];
    activeExitNode: Network | null;
    refresh: () => Promise<void>;
    toggleNetwork: (id: string, selected: boolean) => Promise<void>;
    toggleExitNode: (id: string, selected: boolean) => Promise<void>;
    setNetworksSelected: (ids: string[], selected: boolean) => Promise<void>;
};

const NetworksContext = createContext<NetworksContextValue | null>(null);

export const useNetworks = () => {
    const ctx = useContext(NetworksContext);
    if (!ctx) {
        throw new Error("useNetworks must be used inside NetworksProvider");
    }
    return ctx;
};

export const NetworksProvider = ({ children }: { children: ReactNode }) => {
    const { status } = useStatus();
    const [routes, setRoutes] = useState<Network[]>([]);
    const [pending, setPending] = useState<Map<string, boolean>>(new Map());
    const pendingRef = useRef(pending);
    useEffect(() => {
        pendingRef.current = pending;
    }, [pending]);

    // Safety timer: if a prediction diverges from the daemon, the override would mask the true value forever.
    const STUCK_OVERRIDE_MS = 4000;
    const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

    const clearTimer = useCallback((id: string) => {
        const tid = timersRef.current.get(id);
        if (tid !== undefined) {
            clearTimeout(tid);
            timersRef.current.delete(id);
        }
    }, []);

    const clearPendingFor = useCallback(
        (ids: string[]) => {
            for (const id of ids) clearTimer(id);
            setPending((prev) => {
                if (ids.every((id) => !prev.has(id))) return prev;
                const next = new Map(prev);
                for (const id of ids) next.delete(id);
                return next;
            });
        },
        [clearTimer],
    );

    const setPendingFor = useCallback(
        (updates: Array<[string, boolean]>) => {
            setPending((prev) => {
                const next = new Map(prev);
                for (const [id, sel] of updates) next.set(id, sel);
                return next;
            });
            for (const [id] of updates) {
                clearTimer(id);
                timersRef.current.set(
                    id,
                    setTimeout(() => clearPendingFor([id]), STUCK_OVERRIDE_MS),
                );
            }
        },
        [clearTimer, clearPendingFor],
    );

    useEffect(() => {
        const timers = timersRef.current;
        return () => {
            for (const tid of timers.values()) clearTimeout(tid);
            timers.clear();
        };
    }, []);

    const refresh = useCallback(async () => {
        try {
            const list = await NetworksSvc.List();
            setRoutes(list);
        } catch (e) {
            console.error("[NetworksContext] refresh failed", e);
        }
    }, []);

    const networksRevision = status?.networksRevision;
    useEffect(() => {
        refresh().catch((err: unknown) => console.error("[NetworksContext] refresh failed", err));
    }, [refresh, networksRevision]);

    useEffect(() => {
        if (pendingRef.current.size === 0) return;
        const confirmed: string[] = [];
        for (const r of routes) {
            const expected = pendingRef.current.get(r.id);
            if (expected !== undefined && r.selected === expected) {
                confirmed.push(r.id);
            }
        }
        if (confirmed.length > 0) clearPendingFor(confirmed);
    }, [routes, clearPendingFor]);

    const mutate = useCallback(
        async (ids: string[], selected: boolean, rollback: Array<[string, boolean]>) => {
            try {
                if (selected) {
                    await NetworksSvc.Select({ networkIds: ids, append: true, all: false });
                } else {
                    await NetworksSvc.Deselect({ networkIds: ids, append: false, all: false });
                }
                // Don't clear pending here — let the snapshot-match effect confirm, else a refresh racing the RPC return flashes back.
                await refresh();
            } catch (e) {
                console.error(e);
                setPending((prev) => {
                    const next = new Map(prev);
                    for (const [id] of rollback) next.delete(id);
                    return next;
                });
                throw e;
            }
        },
        [refresh],
    );

    const toggleNetwork = useCallback(
        async (id: string, selected: boolean) => {
            const target = !selected;
            setPendingFor([[id, target]]);
            await mutate([id], target, [[id, selected]]).catch(() => {});
        },
        [mutate, setPendingFor],
    );

    const setNetworksSelected = useCallback(
        async (ids: string[], selected: boolean) => {
            if (ids.length === 0) return;
            const prevById = new Map(routes.map((r) => [r.id, r.selected]));
            const rollback: Array<[string, boolean]> = ids.map((id) => [
                id,
                prevById.get(id) ?? !selected,
            ]);
            setPendingFor(ids.map((id) => [id, selected]));
            await mutate(ids, selected, rollback).catch(() => {});
        },
        [mutate, setPendingFor, routes],
    );

    // Daemon enforces exit-node mutual exclusion; mirror it locally so the optimistic paint matches.
    const toggleExitNode = useCallback(
        async (id: string, selected: boolean) => {
            const target = !selected;
            const updates: Array<[string, boolean]> = [[id, target]];
            const rollback: Array<[string, boolean]> = [[id, selected]];
            if (target) {
                for (const r of routes) {
                    if (r.id !== id && isExitNode(r.range) && r.selected) {
                        updates.push([r.id, false]);
                        rollback.push([r.id, true]);
                    }
                }
            }
            setPendingFor(updates);
            await mutate([id], target, rollback).catch(() => {});
        },
        [mutate, setPendingFor, routes],
    );

    const value = useMemo<NetworksContextValue>(() => {
        const effective =
            pending.size === 0
                ? routes
                : routes.map((r) => {
                      const override = pending.get(r.id);
                      return override === undefined || override === r.selected
                          ? r
                          : { ...r, selected: override };
                  });
        const networkRoutes = effective.filter((r) => !isExitNode(r.range));
        const exitNodes = effective.filter((r) => isExitNode(r.range));
        const activeExitNode = exitNodes.find((r) => r.selected) ?? null;
        return {
            routes: effective,
            networkRoutes,
            exitNodes,
            activeExitNode,
            refresh,
            toggleNetwork,
            toggleExitNode,
            setNetworksSelected,
        };
    }, [routes, pending, refresh, toggleNetwork, toggleExitNode, setNetworksSelected]);

    return <NetworksContext.Provider value={value}>{children}</NetworksContext.Provider>;
};
