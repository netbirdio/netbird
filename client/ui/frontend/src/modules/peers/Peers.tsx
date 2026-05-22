import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/SearchInput";
import { useStatus } from "@/modules/daemon-status/StatusContext";
import { PeerFilters, StatusFilter } from "./PeerFilters";
import { PeersList } from "./PeersList";

const isOnline = (connStatus: string) => connStatus === "Connected";

export const Peers = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const [search, setSearch] = useState("");
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
    const searchRef = useRef<HTMLInputElement>(null);

    // Peers is only mounted in advanced view (see layouts/Main.tsx), so a
    // mount-time focus is equivalent to "focus when the user toggles into
    // advanced view".
    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    const peers = status?.peers ?? [];

    const counts = useMemo<Record<StatusFilter, number>>(() => {
        const online = peers.filter((p) => isOnline(p.connStatus)).length;
        return {
            all: peers.length,
            online,
            offline: peers.length - online,
        };
    }, [peers]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return peers.filter((p) => {
            if (statusFilter === "online" && !isOnline(p.connStatus)) return false;
            if (statusFilter === "offline" && isOnline(p.connStatus)) return false;
            if (q && !p.fqdn.toLowerCase().includes(q) && !p.ip.includes(q)) {
                return false;
            }
            return true;
        });
    }, [peers, search, statusFilter]);

    return (
        <div className={"flex flex-col w-full h-full min-h-0 pt-4"}>
            <div className={"flex flex-col gap-3 px-6"}>
                <SearchInput
                    ref={searchRef}
                    placeholder={t("peers.search.placeholder")}
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
