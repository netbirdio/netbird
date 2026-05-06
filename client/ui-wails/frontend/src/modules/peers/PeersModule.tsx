import { useMemo, useState } from "react";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/SearchInput";
import { mockPeers } from "./mockPeers";
import { PeerFilters, StatusFilter } from "./PeerFilters";
import { PeersList } from "./PeersList";

const isOnline = (status: string) => status === "connected";

export const PeersModule = () => {
    const [search, setSearch] = useState("");
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

    const counts = useMemo<Record<StatusFilter, number>>(() => {
        const online = mockPeers.filter((p) => isOnline(p.status)).length;
        return {
            all: mockPeers.length,
            online,
            offline: mockPeers.length - online,
        };
    }, []);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return mockPeers.filter((p) => {
            if (statusFilter === "online" && !isOnline(p.status)) return false;
            if (statusFilter === "offline" && isOnline(p.status)) return false;
            if (q && !p.fqdn.toLowerCase().includes(q) && !p.ip.includes(q)) {
                return false;
            }
            return true;
        });
    }, [search, statusFilter]);

    return (
        <div className={"flex flex-col w-full h-full min-h-0 pt-4"}>
            <div className={"flex flex-col gap-3 px-4"}>
                <SearchInput
                    placeholder={"Search by FQDN or IP…"}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
                <PeerFilters
                    value={statusFilter}
                    onChange={setStatusFilter}
                    counts={counts}
                />
            </div>
            <ScrollArea.Root
                type={"auto"}
                className={"flex-1 min-h-0 overflow-hidden mt-3"}
            >
                <ScrollArea.Viewport className={"h-full w-full"}>
                    <PeersList data={filtered} />
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
