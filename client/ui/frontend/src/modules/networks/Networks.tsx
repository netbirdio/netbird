import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { NetworkIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/SearchInput";
import { EmptyState } from "@/components/EmptyState";
import { NoResults } from "@/components/NoResults";
import { NotConnectedState } from "@/components/NotConnectedState";
import { useStatus } from "@/modules/daemon-status/StatusContext";
import {
    formatShortcut,
    useKeyboardShortcut,
} from "@/lib/useKeyboardShortcut";

const SEARCH_SHORTCUT = { key: "k", cmd: true } as const;
import { NetworkFilter, NetworkFilters } from "./NetworkFilters";
import { NetworksList } from "./NetworksList";
import { useNetworks } from "./NetworksContext";

// Map every range string -> ids of CIDR routes that share it. Domain routes
// are skipped (they overlap on domain, not prefix). Single-entry buckets
// aren't overlaps.
const buildOverlapMap = (
    routes: { id: string; range: string; domains: string[] }[],
): Map<string, string[]> => {
    const byRange = new Map<string, string[]>();
    for (const r of routes) {
        if (r.domains.length > 0) continue;
        const arr = byRange.get(r.range) ?? [];
        arr.push(r.id);
        byRange.set(r.range, arr);
    }
    const out = new Map<string, string[]>();
    for (const [range, ids] of byRange) {
        if (ids.length > 1) out.set(range, ids);
    }
    return out;
};

export const Networks = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const isConnected = status?.status === "Connected";
    const { networkRoutes, toggleNetwork } = useNetworks();
    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState<NetworkFilter>("all");
    const searchRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    useKeyboardShortcut(SEARCH_SHORTCUT, () => {
        searchRef.current?.focus();
        searchRef.current?.select();
    });

    const overlapGroups = useMemo(
        () => buildOverlapMap(networkRoutes),
        [networkRoutes],
    );

    const overlapById = useMemo(() => {
        const map = new Map<string, string[]>();
        for (const ids of overlapGroups.values()) {
            for (const id of ids) map.set(id, ids);
        }
        return map;
    }, [overlapGroups]);

    const counts = useMemo<Record<NetworkFilter, number>>(
        () => ({
            all: networkRoutes.length,
            active: networkRoutes.filter((r) => r.selected).length,
            overlapping: overlapById.size,
        }),
        [networkRoutes, overlapById],
    );

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        const matches = networkRoutes.filter((r) => {
            if (filter === "active" && !r.selected) return false;
            if (filter === "overlapping" && !overlapById.has(r.id)) return false;
            if (q) {
                const haystack = [r.id, r.range, ...r.domains]
                    .join(" ")
                    .toLowerCase();
                if (!haystack.includes(q)) return false;
            }
            return true;
        });
        return matches.sort((a, b) => {
            if (a.selected !== b.selected) return a.selected ? -1 : 1;
            return a.id.localeCompare(b.id);
        });
    }, [networkRoutes, search, filter, overlapById]);

    if (!isConnected) {
        return (
            <div className={"flex flex-col w-full h-full min-h-0"}>
                <NotConnectedState />
            </div>
        );
    }

    if (networkRoutes.length === 0) {
        return (
            <div
                className={
                    "flex-1 flex items-center justify-center px-6 w-full h-full min-h-0"
                }
            >
                <EmptyState
                    icon={NetworkIcon}
                    title={t("networks.empty.title")}
                    description={t("networks.empty.description")}
                    learnMoreUrl={"https://docs.netbird.io/how-to/networks"}
                    learnMoreTopic={t("nav.resources.title")}
                />
            </div>
        );
    }

    return (
        <div className={"flex flex-col w-full h-full min-h-0 pt-4"}>
            <div className={"flex flex-col gap-3 px-6"}>
                <SearchInput
                    ref={searchRef}
                    placeholder={t("networks.search.placeholder")}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    shortcut={formatShortcut(SEARCH_SHORTCUT)}
                />
                <NetworkFilters
                    value={filter}
                    onChange={setFilter}
                    counts={counts}
                />
            </div>
            <ScrollArea.Root
                type={"auto"}
                className={"flex-1 min-h-0 overflow-hidden mt-3"}
            >
                <ScrollArea.Viewport className={"h-full w-full"}>
                    {filtered.length === 0 ? (
                        <NoResults />
                    ) : (
                        <NetworksList
                            data={filtered}
                            onToggle={toggleNetwork}
                        />
                    )}
                </ScrollArea.Viewport>
                <ScrollArea.Scrollbar
                    orientation={"vertical"}
                    className={cn(
                        "flex select-none touch-none transition-colors",
                        "w-1.5 bg-transparent py-1",
                    )}
                >
                    <ScrollArea.Thumb
                        className={
                            "flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative"
                        }
                    />
                </ScrollArea.Scrollbar>
            </ScrollArea.Root>
        </div>
    );
};
