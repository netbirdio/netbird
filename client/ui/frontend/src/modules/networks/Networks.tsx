import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/SearchInput";
import { NetworkFilters, NetworkFilter } from "./NetworkFilters";
import { NetworksList } from "./NetworksList";
import { useNetworks } from "./NetworksContext";

const collectOverlapping = (routes: { id: string; range: string; domains: string[] }[]): Set<string> => {
    const byRange = new Map<string, string[]>();
    for (const r of routes) {
        if (r.domains.length > 0) continue;
        const arr = byRange.get(r.range) ?? [];
        arr.push(r.id);
        byRange.set(r.range, arr);
    }
    const out = new Set<string>();
    for (const ids of byRange.values()) {
        if (ids.length > 1) ids.forEach((id) => out.add(id));
    }
    return out;
};

export const Networks = () => {
    const { t } = useTranslation();
    const { networkRoutes, toggleNetwork } = useNetworks();
    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState<NetworkFilter>("all");
    const searchRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    const overlappingIds = useMemo(
        () => collectOverlapping(networkRoutes),
        [networkRoutes],
    );

    const counts = useMemo<Record<NetworkFilter, number>>(
        () => ({
            all: networkRoutes.length,
            selected: networkRoutes.filter((r) => r.selected).length,
            overlapping: overlappingIds.size,
        }),
        [networkRoutes, overlappingIds],
    );

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        const matches = networkRoutes.filter((r) => {
            if (filter === "selected" && !r.selected) return false;
            if (filter === "overlapping" && !overlappingIds.has(r.id)) return false;
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
    }, [networkRoutes, search, filter, overlappingIds]);

    return (
        <div className={"flex flex-col w-full h-full min-h-0 pt-4"}>
            <div className={"flex flex-col gap-3 px-6"}>
                <SearchInput
                    ref={searchRef}
                    placeholder={t("networks.search.placeholder")}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
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
                    <NetworksList data={filtered} onToggle={toggleNetwork} />
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
