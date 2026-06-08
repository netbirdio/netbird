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
import { latencyColor, shortenDns } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { usePeerDetail } from "@/contexts/PeerDetailContext";
import { Tooltip } from "@/components/Tooltip";
import { TruncatedText } from "@/components/TruncatedText";
import { mockOr, mockPeers } from "@/lib/mock";
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

// The daemon reports "Idle" for not-connected peers; surface it as
// "Disconnected" in the UI. Connected / Connecting pass through.
export const peerStatusLabelKey = (connStatus: string): string => {
    switch (connStatus) {
        case "Connected":
            return "peers.status.connected";
        case "Connecting":
            return "peers.status.connecting";
        default:
            return "peers.status.disconnected";
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
    const peers = mockOr(status?.peers ?? [], mockPeers);

    const counts = useMemo<Record<StatusFilter, number>>(() => {
        const online = peers.filter((p) => isOnline(p.connStatus)).length;
        return {
            all: peers.length,
            online,
            offline: peers.length - online,
        };
    }, [peers]);

    // Initial order: online-first, then alphabetically by fqdn / ip. Once
    // peers have settled, positions become sticky — a peer flipping
    // Connected→Connecting→Idle no longer jumps groups. Newly discovered
    // peers append at the end (sorted online-first / by-name among
    // themselves). Mirrors the networks-list and exit-nodes-list orderRef
    // pattern.
    //
    // Stay in live-sort mode until every peer has reached a stable state
    // (Connected or Idle). The daemon emits all peers as "Connecting" right
    // after Up, which collapses the online-first sort into pure
    // alphabetical — committing then would lock that incorrect order and
    // the list would stay alphabetical even after every peer becomes
    // Connected. Once nothing is Connecting we commit and go sticky.
    const orderRef = useRef<string[]>([]);
    const stickyRef = useRef(false);
    const ordered = useMemo(() => {
        const sortOnlineFirst = (list: PeerStatus[]) =>
            [...list].sort((a, b) => {
                const aOnline = isOnline(a.connStatus);
                const bOnline = isOnline(b.connStatus);
                if (aOnline !== bOnline) return aOnline ? -1 : 1;
                const aName = (a.fqdn || a.ip).toLowerCase();
                const bName = (b.fqdn || b.ip).toLowerCase();
                return aName.localeCompare(bName);
            });

        // Reset on empty (Disconnect → reconnect) so the next session
        // re-sorts from scratch instead of replaying the stale orderRef.
        if (peers.length === 0) {
            orderRef.current = [];
            stickyRef.current = false;
            return [];
        }

        if (!stickyRef.current) {
            const sorted = sortOnlineFirst(peers);
            if (peers.every((p) => p.connStatus !== "Connecting")) {
                orderRef.current = sorted.map((p) => p.pubKey);
                stickyRef.current = true;
            }
            return sorted;
        }

        const byKey = new Map(peers.map((p) => [p.pubKey, p]));
        const kept = orderRef.current.filter((k) => byKey.has(k));
        const known = new Set(kept);
        const fresh = sortOnlineFirst(peers.filter((p) => !known.has(p.pubKey))).map(
            (p) => p.pubKey,
        );
        const next = [...kept, ...fresh];
        orderRef.current = next;
        return next.map((k) => byKey.get(k)!);
    }, [peers]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return ordered.filter((p) => {
            if (statusFilter === "online" && !isOnline(p.connStatus)) return false;
            if (statusFilter === "offline" && isOnline(p.connStatus)) return false;
            if (q && !p.fqdn.toLowerCase().includes(q) && !p.ip.includes(q)) {
                return false;
            }
            return true;
        });
    }, [ordered, search, statusFilter]);

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
    const { t } = useTranslation();
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
                            "group flex items-start gap-2.5 pl-6 pr-4 py-3 min-w-0 first:mt-2",
                            "hover:bg-nb-gray-900/40 transition-colors",
                            "wails-no-draggable cursor-default",
                        )}
                    >
                        <Tooltip content={t(peerStatusLabelKey(peer.connStatus))} side={"left"}>
                            <span
                                className={cn(
                                    "h-2 w-2 rounded-full shrink-0 mt-2",
                                    dotClass(peer.connStatus),
                                )}
                            />
                        </Tooltip>
                        <div className={"min-w-0 flex-1 flex flex-col leading-tight"}>
                            <div>
                                <CopyToClipboard message={peer.fqdn}>
                                    <TruncatedText
                                        text={shortenDns(peer.fqdn)}
                                        className={
                                            "block text-[0.81rem] font-medium text-nb-gray-100 truncate max-w-[300px]"
                                        }
                                    />
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
