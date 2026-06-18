import { KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Virtuoso, VirtuosoHandle } from "react-virtuoso";
import { ChevronRightIcon, MonitorSmartphoneIcon } from "lucide-react";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { reconcileOrder } from "@/lib/sorting";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { SearchInput } from "@/components/inputs/SearchInput";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { NoResults } from "@/components/empty-state/NoResults";
import { latencyColor, shortenDns } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { usePeerDetail } from "@/contexts/PeerDetailContext";
import { Tooltip } from "@/components/Tooltip";
import { TruncatedText } from "@/components/TruncatedText";
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
    const [scrollParent, setScrollParent] = useState<HTMLDivElement | null>(null);
    const searchRef = useRef<HTMLInputElement>(null);

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

    // Stay in live-sort until every peer is stable. Right after Up the daemon
    // emits all peers as "Connecting"; committing then would lock that
    // alphabetical-only order forever.
    const orderRef = useRef<string[]>([]);
    const stickyRef = useRef(false);
    const ordered = useMemo(() => {
        const compare = (a: PeerStatus, b: PeerStatus) => {
            const aOnline = isOnline(a.connStatus);
            const bOnline = isOnline(b.connStatus);
            if (aOnline !== bOnline) return aOnline ? -1 : 1;
            const aName = (a.fqdn || a.ip).toLowerCase();
            const bName = (b.fqdn || b.ip).toLowerCase();
            return aName.localeCompare(bName);
        };

        if (peers.length === 0) {
            orderRef.current = [];
            stickyRef.current = false;
            return [];
        }

        if (!stickyRef.current) {
            const sorted = [...peers].sort(compare);
            if (peers.every((p) => p.connStatus !== "Connecting")) {
                orderRef.current = sorted.map((p) => p.pubKey);
                stickyRef.current = true;
            }
            return sorted;
        }

        const { order, items } = reconcileOrder(orderRef.current, peers, (p) => p.pubKey, compare);
        orderRef.current = order;
        return items;
    }, [peers]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return ordered.filter((p) => {
            if (statusFilter === "online" && !isOnline(p.connStatus)) return false;
            if (statusFilter === "offline" && isOnline(p.connStatus)) return false;
            return !q || p.fqdn.toLowerCase().includes(q) || p.ip.includes(q);
        });
    }, [ordered, search, statusFilter]);

    if (isConnected && peers.length === 0) {
        return (
            <EmptyState
                icon={MonitorSmartphoneIcon}
                title={t("peers.empty.title")}
                description={t("peers.empty.description")}
            />
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
            {filtered.length === 0 ? (
                <NoResults />
            ) : (
                <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                    <ScrollArea.Viewport ref={setScrollParent} className={"h-full w-full"}>
                        {scrollParent && <PeersList data={filtered} scrollParent={scrollParent} />}
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
            )}
        </div>
    );
};

const ListTopSpacer = () => <div className={"h-2"} />;

type PeersListProps = {
    data: PeerStatus[];
    scrollParent: HTMLElement;
};

const PeersList = ({ data, scrollParent }: PeersListProps) => {
    const { t } = useTranslation();
    const { setSelected } = usePeerDetail();
    const virtuosoRef = useRef<VirtuosoHandle>(null);
    const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());

    const focusRow = (index: number) => {
        if (index < 0 || index >= data.length) return;
        const peer = data[index];
        const tryFocus = () => {
            const el = rowRefs.current.get(peer.pubKey);
            if (el) {
                el.focus();
                return true;
            }
            return false;
        };
        if (!tryFocus()) {
            virtuosoRef.current?.scrollToIndex({ index, behavior: "auto" });
            // Row may not be mounted yet — retry after Virtuoso renders it.
            requestAnimationFrame(() => {
                if (!tryFocus()) requestAnimationFrame(tryFocus);
            });
        }
    };

    const handleRowKeyDown = (e: KeyboardEvent<HTMLDivElement>, index: number) => {
        switch (e.key) {
            case "ArrowDown":
                e.preventDefault();
                focusRow(Math.min(index + 1, data.length - 1));
                break;
            case "ArrowUp":
                e.preventDefault();
                focusRow(Math.max(index - 1, 0));
                break;
            case "ArrowRight":
                e.preventDefault();
                setSelected(data[index]);
                break;
            case "Home":
                e.preventDefault();
                focusRow(0);
                break;
            case "End":
                e.preventDefault();
                focusRow(data.length - 1);
                break;
        }
    };

    return (
        <Virtuoso
            ref={virtuosoRef}
            data={data}
            customScrollParent={scrollParent}
            increaseViewportBy={400}
            computeItemKey={(_, peer) => peer.pubKey}
            components={{ Header: ListTopSpacer }}
            itemContent={(index, peer) => {
                const isConnected = peer.connStatus === "Connected";
                const peerName = shortenDns(peer.fqdn) || peer.ip;
                const statusLabel = t(peerStatusLabelKey(peer.connStatus));
                return (
                    <div
                        role="listitem"
                        onKeyDown={(e) => handleRowKeyDown(e, index)}
                        className={cn(
                            "group relative flex items-start gap-2.5 pl-6 pr-4 py-3 min-w-0",
                            "hover:bg-nb-gray-900/40 transition-colors",
                            "wails-no-draggable",
                        )}
                    >
                        <button
                            type={"button"}
                            tabIndex={0}
                            ref={(el) => {
                                if (el) rowRefs.current.set(peer.pubKey, el);
                                else rowRefs.current.delete(peer.pubKey);
                            }}
                            aria-label={t("peers.row.label", {
                                name: peerName,
                                status: statusLabel,
                            })}
                            onClick={() => setSelected(peer)}
                            className={cn(
                                "absolute inset-0 cursor-default outline-none",
                                "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
                            )}
                        />
                        <Tooltip content={statusLabel} side={"left"}>
                            <span
                                role="img"
                                aria-label={statusLabel}
                                className={cn(
                                    "h-2 w-2 rounded-full shrink-0 mt-2 relative",
                                    dotClass(peer.connStatus),
                                )}
                            />
                        </Tooltip>
                        <div
                            className={
                                "min-w-0 flex-1 flex flex-col leading-tight relative pointer-events-none"
                            }
                        >
                            <div>
                                <CopyToClipboard
                                    message={peer.fqdn}
                                    className={"pointer-events-auto"}
                                >
                                    <TruncatedText
                                        text={shortenDns(peer.fqdn)}
                                        className={
                                            "block text-[0.81rem] font-medium text-nb-gray-100 truncate max-w-[300px]"
                                        }
                                    />
                                </CopyToClipboard>
                            </div>
                            <div>
                                <CopyToClipboard
                                    message={peer.ip}
                                    className={"pointer-events-auto"}
                                >
                                    <span className={"text-xs font-mono text-nb-gray-400 truncate"}>
                                        {peer.ip}
                                    </span>
                                </CopyToClipboard>
                            </div>
                        </div>
                        {isConnected && peer.latencyMs > 0 && (
                            <span
                                className={cn(
                                    "shrink-0 self-center text-xs tabular-nums relative pointer-events-none",
                                    latencyColor(peer.latencyMs),
                                )}
                            >
                                {peer.latencyMs} ms
                            </span>
                        )}
                        <ChevronRightIcon
                            size={16}
                            aria-hidden="true"
                            className={cn(
                                "shrink-0 self-center text-nb-gray-300 relative pointer-events-none",
                                "opacity-0 group-hover:opacity-100 transition-opacity",
                            )}
                        />
                    </div>
                );
            }}
        />
    );
};
