import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { ChevronRightIcon, LaptopIcon } from "lucide-react";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { SearchInput } from "@/components/inputs/SearchInput";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { NoResults } from "@/components/empty-state/NoResults";
import { latencyColor } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { usePeerDetail } from "@/contexts/PeerDetailContext";
import { PeerFilters, StatusFilter } from "./PeerFilters";

const isOnline = (connStatus: string) => connStatus === "Connected";

const dotClass = (connStatus: string): string => {
    switch (connStatus) {
        case "Connected":
            return "bg-green-400";
        case "Connecting":
            return "bg-yellow-300 animate-pulse-slow";
        default:
            return "bg-nb-gray-500";
    }
};

export const Peers = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const [search, setSearch] = useState("");
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
    const searchRef = useRef<HTMLInputElement>(null);

    // Peers is only mounted in advanced view (see pages/Main.tsx), so a
    // mount-time focus is equivalent to "focus when the user toggles into
    // advanced view".
    useEffect(() => {
        searchRef.current?.focus();
    }, []);

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

    if (isConnected && peers.length === 0) {
        return (
            <div
                className={
                    "flex-1 flex items-center justify-center px-6 pb-20 w-full h-full min-h-0"
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
        <div className={"flex flex-col w-full h-full min-h-0"}>
            <div className={"flex items-center gap-2 px-6 py-2.5 border-b border-nb-gray-910"}>
                <div className={"flex-1 min-w-0"}>
                    <SearchInput
                        ref={searchRef}
                        placeholder={t("peers.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <PeerFilters value={statusFilter} onChange={setStatusFilter} counts={counts} />
            </div>
            <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                <ScrollArea.Viewport className={"h-full w-full"}>
                    {filtered.length === 0 ? <NoResults /> : <PeersList data={filtered} />}
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

const PeersList = ({ data }: { data: PeerStatus[] }) => {
    const { setSelected } = usePeerDetail();

    return (
        <ul className={"flex flex-col"}>
            {data.map((peer) => {
                const isConnected = peer.connStatus === "Connected";
                return (
                    <li
                        key={peer.pubKey}
                        onClick={() => setSelected(peer)}
                        className={cn(
                            "group flex items-start gap-2.5 px-7 py-3 min-w-0 first:mt-2",
                            "hover:bg-nb-gray-900/40 transition-colors",
                            "wails-no-draggable cursor-pointer",
                        )}
                    >
                        <span
                            className={cn(
                                "h-2 w-2 rounded-full shrink-0 mt-2",
                                dotClass(peer.connStatus),
                            )}
                            title={peer.connStatus}
                        />
                        <div className={"min-w-0 flex-1 flex flex-col leading-tight"}>
                            <div>
                                <CopyToClipboard message={peer.fqdn}>
                                    <span
                                        className={
                                            "text-[0.81rem] font-medium text-nb-gray-100 truncate"
                                        }
                                    >
                                        {peer.fqdn}
                                    </span>
                                </CopyToClipboard>
                            </div>
                            <div>
                                <CopyToClipboard message={peer.ip}>
                                    <span className={"text-xs font-mono text-nb-gray-400 truncate"}>
                                        {peer.ip}
                                    </span>
                                </CopyToClipboard>
                            </div>
                        </div>
                        {isConnected && peer.latencyMs > 0 && (
                            <span
                                className={cn(
                                    "shrink-0 self-center text-xs tabular-nums",
                                    latencyColor(peer.latencyMs),
                                )}
                            >
                                {peer.latencyMs} ms
                            </span>
                        )}
                        <ChevronRightIcon
                            size={16}
                            className={cn(
                                "shrink-0 self-center text-nb-gray-300",
                                "opacity-0 group-hover:opacity-100 transition-opacity",
                            )}
                        />
                    </li>
                );
            })}
        </ul>
    );
};
