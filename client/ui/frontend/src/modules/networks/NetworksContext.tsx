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
import { useStatus } from "@/modules/daemon-status/StatusContext";

// A range is treated as an exit-node candidate when any of its CIDRs is a
// default route (v4 or v6). The daemon may merge a v4+v6 pair into a single
// comma-joined range string for one peer.
export const isDefaultRoute = (range: string): boolean =>
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
    // Optimistic overrides: id → expected `selected` value. Applied on top of
    // the server-side `routes` so toggles paint instantly. Entries are cleared
    // either when the next server snapshot agrees (success path) or when the
    // RPC throws (rollback). Linear-style optimistic mutation tracking.
    const [pending, setPending] = useState<Map<string, boolean>>(new Map());
    // Mirror of `pending` for use inside async callbacks without re-binding
    // them on every change.
    const pendingRef = useRef(pending);
    useEffect(() => {
        pendingRef.current = pending;
    }, [pending]);

    const setPendingFor = useCallback((updates: Array<[string, boolean]>) => {
        setPending((prev) => {
            const next = new Map(prev);
            for (const [id, sel] of updates) next.set(id, sel);
            return next;
        });
    }, []);

    const clearPendingFor = useCallback((ids: string[]) => {
        setPending((prev) => {
            if (ids.every((id) => !prev.has(id))) return prev;
            const next = new Map(prev);
            for (const id of ids) next.delete(id);
            return next;
        });
    }, []);

    const refresh = useCallback(async () => {
        try {
            const list = await NetworksSvc.List();
            setRoutes(list);
        } catch (e) {
            console.error("[NetworksContext] refresh failed", e);
        }
    }, []);

    // The daemon bumps networksRevision whenever the routed-network set or a
    // selection changes (from any surface) and pushes it on the status stream.
    // Refetch on every bump so the list stays live without polling — and on
    // mount, since the revision is already defined by the time this provider
    // renders (StatusProvider only mounts children once the daemon is reachable).
    const networksRevision = status?.networksRevision;
    useEffect(() => {
        void refresh();
    }, [refresh, networksRevision]);

    // When the server snapshot agrees with a pending optimistic value, the
    // mutation is confirmed — drop the override so the row tracks the server
    // again. Runs whenever routes change.
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
                // Don't clear pending here — let the revision-driven refresh
                // confirm via the snapshot-match effect. That avoids a flash
                // back to old state if the refresh races the RPC return.
                await refresh();
            } catch (e) {
                console.error(e);
                // Roll back to the last server-observed value for each id.
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

    // Batch toggle for the bottom-bar select-all switch. The daemon's
    // Select/Deselect RPCs accept an ID list natively, so we don't fan out
    // per-ID calls — one round-trip + one refresh.
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

    // Exit nodes are mutually exclusive, but the daemon enforces that now —
    // selecting one deselects the other exit nodes. Append so activating an
    // exit node doesn't wipe the user's network-route selections. We also
    // mirror that mutual-exclusion locally so the optimistic paint matches
    // the daemon's eventual state.
    const toggleExitNode = useCallback(
        async (id: string, selected: boolean) => {
            const target = !selected;
            const updates: Array<[string, boolean]> = [[id, target]];
            const rollback: Array<[string, boolean]> = [[id, selected]];
            if (target) {
                for (const r of routes) {
                    if (r.id !== id && isDefaultRoute(r.range) && r.selected) {
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
        // Apply pending overrides on top of the server snapshot. The override
        // map is usually empty or tiny (one entry per in-flight toggle), so
        // the per-route lookup is effectively free.
        const effective =
            pending.size === 0
                ? routes
                : routes.map((r) => {
                      const override = pending.get(r.id);
                      return override === undefined || override === r.selected
                          ? r
                          : { ...r, selected: override };
                  });
        const networkRoutes = effective.filter((r) => !isDefaultRoute(r.range));
        const exitNodes = effective.filter((r) => isDefaultRoute(r.range));
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
