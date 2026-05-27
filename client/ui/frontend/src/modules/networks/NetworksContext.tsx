import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
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

    const refresh = useCallback(async () => {
        try {
            const list = await NetworksSvc.List();
            setRoutes(list);
        } catch (e) {
            console.error(e);
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

    const toggleNetwork = useCallback(
        async (id: string, selected: boolean) => {
            try {
                if (selected) {
                    await NetworksSvc.Deselect({
                        networkIds: [id],
                        append: false,
                        all: false,
                    });
                } else {
                    await NetworksSvc.Select({
                        networkIds: [id],
                        append: true,
                        all: false,
                    });
                }
                await refresh();
            } catch (e) {
                console.error(e);
            }
        },
        [refresh],
    );

    // Exit nodes are mutually exclusive — Select with append=false clears any
    // other selection before activating the new one.
    const toggleExitNode = useCallback(
        async (id: string, selected: boolean) => {
            try {
                if (selected) {
                    await NetworksSvc.Deselect({
                        networkIds: [id],
                        append: false,
                        all: false,
                    });
                } else {
                    await NetworksSvc.Select({
                        networkIds: [id],
                        append: false,
                        all: false,
                    });
                }
                await refresh();
            } catch (e) {
                console.error(e);
            }
        },
        [refresh],
    );

    const value = useMemo<NetworksContextValue>(() => {
        const networkRoutes = routes.filter((r) => !isDefaultRoute(r.range));
        const exitNodes = routes.filter((r) => isDefaultRoute(r.range));
        const activeExitNode = exitNodes.find((r) => r.selected) ?? null;
        return {
            routes,
            networkRoutes,
            exitNodes,
            activeExitNode,
            refresh,
            toggleNetwork,
            toggleExitNode,
        };
    }, [routes, refresh, toggleNetwork, toggleExitNode]);

    return <NetworksContext.Provider value={value}>{children}</NetworksContext.Provider>;
};
