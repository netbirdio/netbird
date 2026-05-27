import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { LaptopIcon } from "lucide-react";
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
import { PeerFilters, StatusFilter } from "./PeerFilters";
import { PeersList } from "./PeersList";

const isOnline = (connStatus: string) => connStatus === "Connected";

const SEARCH_SHORTCUT = { key: "k", cmd: true } as const;

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

    useKeyboardShortcut(SEARCH_SHORTCUT, () => {
        searchRef.current?.focus();
        searchRef.current?.select();
    });

    const isConnected = status?.status === "Connected";
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
        const matches = peers.filter((p) => {
            if (statusFilter === "online" && !isOnline(p.connStatus)) return false;
            if (statusFilter === "offline" && isOnline(p.connStatus)) return false;
            if (q && !p.fqdn.toLowerCase().includes(q) && !p.ip.includes(q)) {
                return false;
            }
            return true;
        });
        return matches.sort((a, b) => {
            const aOnline = isOnline(a.connStatus);
            const bOnline = isOnline(b.connStatus);
            if (aOnline !== bOnline) return aOnline ? -1 : 1;
            const aName = (a.fqdn || a.ip).toLowerCase();
            const bName = (b.fqdn || b.ip).toLowerCase();
            return aName.localeCompare(bName);
        });
    }, [peers, search, statusFilter]);

    if (!isConnected) {
        return (
            <div className={"flex flex-col w-full h-full min-h-0"}>
                <NotConnectedState />
            </div>
        );
    }

    if (peers.length === 0) {
        return (
            <div
                className={
                    "flex-1 flex items-center justify-center px-6 w-full h-full min-h-0"
                }
            >
                <EmptyState
                    icon={LaptopIcon}
                    title={t("peers.empty.title")}
                    description={t("peers.empty.description")}
                    learnMoreUrl={"https://docs.netbird.io/how-to/getting-started"}
                    learnMoreTopic={t("nav.peers.title")}
                />
            </div>
        );
    }

    return (
        <div className={"flex flex-col w-full h-full min-h-0 pt-4"}>
            <div className={"flex flex-col gap-3 px-6"}>
                <SearchInput
                    ref={searchRef}
                    placeholder={t("peers.search.placeholder")}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    shortcut={formatShortcut(SEARCH_SHORTCUT)}
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
                    {filtered.length === 0 ? (
                        <NoResults />
                    ) : (
                        <PeersList data={filtered} />
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
