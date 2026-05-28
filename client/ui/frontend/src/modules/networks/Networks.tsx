import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { NetworkIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/SearchInput";
import { EmptyState } from "@/components/EmptyState";
import { NoResults } from "@/components/NoResults";
import { useStatus } from "@/modules/daemon-status/StatusContext";
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
    const { networkRoutes, toggleNetwork, setNetworksSelected } = useNetworks();
    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState<NetworkFilter>("all");
    const searchRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    const overlapGroups = useMemo(() => buildOverlapMap(networkRoutes), [networkRoutes]);

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

    // Initial order: active-first, then by id. After that, positions are sticky
    // — toggling a row doesn't move it, and newly discovered routes append at
    // the end (sorted active-first / by-id among themselves). The ref carries
    // the previous order across renders so the reconciliation is synchronous
    // with networkRoutes updates (no useEffect lag → no visual hop).
    const orderRef = useRef<string[]>([]);
    const ordered = useMemo(() => {
        const byId = new Map(networkRoutes.map((r) => [r.id, r]));
        const kept = orderRef.current.filter((id) => byId.has(id));
        const known = new Set(kept);
        const fresh = networkRoutes
            .filter((r) => !known.has(r.id))
            .sort((a, b) => {
                if (a.selected !== b.selected) return a.selected ? -1 : 1;
                return a.id.localeCompare(b.id);
            })
            .map((r) => r.id);
        const next = [...kept, ...fresh];
        orderRef.current = next;
        return next.map((id) => byId.get(id)!);
    }, [networkRoutes]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return ordered.filter((r) => {
            if (filter === "active" && !r.selected) return false;
            if (filter === "overlapping" && !overlapById.has(r.id)) return false;
            if (q) {
                const haystack = [r.id, r.range, ...r.domains].join(" ").toLowerCase();
                if (!haystack.includes(q)) return false;
            }
            return true;
        });
    }, [ordered, search, filter, overlapById]);

    if (isConnected && networkRoutes.length === 0) {
        return (
            <div
                className={
                    "flex-1 flex items-center justify-center px-6 pb-20 w-full h-full min-h-0"
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

    const selectedInView = filtered.filter((r) => r.selected).length;
    const allSelected = filtered.length > 0 && selectedInView === filtered.length;
    const bulkLabel = allSelected
        ? t("networks.bulk.disableAll")
        : t("networks.bulk.enableAll");

    const onBulkClick = () => {
        if (filtered.length === 0) return;
        if (allSelected) {
            void setNetworksSelected(
                filtered.map((r) => r.id),
                false,
            );
        } else {
            const ids = filtered.filter((r) => !r.selected).map((r) => r.id);
            void setNetworksSelected(ids, true);
        }
    };

    return (
        <div className={"flex flex-col w-full h-full min-h-0"}>
            <div className={"flex items-center gap-2 px-6 py-2.5 border-b border-nb-gray-910"}>
                <div className={"flex-1 min-w-0"}>
                    <SearchInput
                        ref={searchRef}
                        placeholder={t("networks.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <NetworkFilters value={filter} onChange={setFilter} counts={counts} />
            </div>
            <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                <ScrollArea.Viewport className={"h-full w-full"}>
                    {filtered.length === 0 ? (
                        <NoResults />
                    ) : (
                        <NetworksList data={filtered} onToggle={toggleNetwork} />
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
            {filtered.length > 0 && (
                <div
                    className={cn(
                        "flex items-center gap-3 px-6 py-3.5",
                        "border-t border-nb-gray-910",
                    )}
                >
                    <span className={"flex-1 text-xs font-medium text-nb-gray-300 tabular-nums"}>
                        {t("networks.bulk.selectionCount", {
                            selected: selectedInView,
                            total: filtered.length,
                        })}
                    </span>
                    <button
                        type={"button"}
                        onClick={onBulkClick}
                        className={cn(
                            "inline-flex items-center h-8 px-3 rounded-md",
                            "text-xs font-medium text-nb-gray-100",
                            "bg-nb-gray-920 hover:bg-nb-gray-910 border border-nb-gray-900 hover:border-nb-gray-850",
                            "transition-colors outline-none wails-no-draggable cursor-pointer",
                        )}
                    >
                        {bulkLabel}
                    </button>
                </div>
            )}
        </div>
    );
};
