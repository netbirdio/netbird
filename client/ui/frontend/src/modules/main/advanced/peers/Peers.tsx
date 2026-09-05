import {
    type DragEvent,
    type KeyboardEvent,
    useCallback,
    useEffect,
    useMemo,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";
import { Events } from "@wailsio/runtime";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Virtuoso, type VirtuosoHandle } from "react-virtuoso";
import { ChevronRightIcon, MonitorSmartphoneIcon, SendIcon } from "lucide-react";
import { FileDrop } from "@bindings/services";
import type { PeerStatus } from "@bindings/services/models.js";
import { useNavSection } from "@/contexts/NavSectionContext";
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
import { PeerFilters, type StatusFilter } from "./PeerFilters";

const isOnline = (connStatus: string) => connStatus === "Connected";

export const dotClass = (connStatus: string): string => {
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

const EVENT_FILES_DROPPED = "netbird:files:dropped";

export const Peers = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const { setSection } = useNavSection();
    const [search, setSearch] = useState("");
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
    const [scrollParent, setScrollParent] = useState<HTMLDivElement | null>(null);
    const searchRef = useRef<HTMLInputElement>(null);
    const [dropTarget, setDropTarget] = useState<string | null>(null);
    const dropTargetRef = useRef<string | null>(null);

    const setDropTargetBoth = useCallback((pubKey: string | null) => {
        dropTargetRef.current = pubKey;
        setDropTarget(pubKey);
    }, []);

    useEffect(() => {
        const off = Events.On(EVENT_FILES_DROPPED, (ev: { data: string[] | string[][] }) => {
            const target = dropTargetRef.current;
            setDropTargetBoth(null);
            if (!target) return;
            const raw = ev.data;
            const paths = (Array.isArray(raw[0]) ? raw[0] : raw) as string[];
            if (paths.length === 0) return;
            void FileDrop.Send(target, paths, "").then(() => setSection("files"));
        });
        return off;
    }, [setDropTargetBoth, setSection]);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    const isConnected = status?.status === "Connected";
    const peers = useMemo(() => status?.peers ?? [], [status?.peers]);

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
        <div className={"flex h-full min-h-0 w-full flex-col"}>
            <div className={"flex items-center gap-2 border-b border-nb-gray-910 px-6 py-2.5"}>
                <div className={"min-w-0 flex-1"}>
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
                <ScrollArea.Root
                    type={"auto"}
                    className={"min-h-0 flex-1 overflow-hidden"}
                    onDragLeave={(e: DragEvent) => {
                        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
                            setDropTargetBoth(null);
                        }
                    }}
                    onDragOver={(e: DragEvent) => e.preventDefault()}
                    onDrop={(e: DragEvent) => e.preventDefault()}
                >
                    <ScrollArea.Viewport ref={setScrollParent} className={"h-full w-full"}>
                        {scrollParent && (
                            <PeersList
                                data={filtered}
                                scrollParent={scrollParent}
                                dropTarget={dropTarget}
                                onDropTarget={setDropTargetBoth}
                            />
                        )}
                    </ScrollArea.Viewport>
                    <ScrollArea.Scrollbar
                        orientation={"vertical"}
                        className={cn(
                            "flex touch-none select-none transition-colors",
                            "w-1.5 bg-transparent py-1",
                        )}
                    >
                        <ScrollArea.Thumb
                            className={
                                "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
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
    dropTarget: string | null;
    onDropTarget: (pubKey: string | null) => void;
};

const PeersList = ({ data, scrollParent, dropTarget, onDropTarget }: PeersListProps) => {
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

    const handleRowKeyDown = (e: KeyboardEvent<Element>, index: number) => {
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

    const setRowRef = (pubKey: string, el: HTMLButtonElement | null) => {
        if (el) rowRefs.current.set(pubKey, el);
        else rowRefs.current.delete(pubKey);
    };

    const ctx = useMemo<PeerRowContext>(
        () => ({
            onKeyDown: handleRowKeyDown,
            onSelect: setSelected,
            setRowRef,
            dropTarget,
            onDropTarget,
        }),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [data, setSelected, dropTarget, onDropTarget],
    );

    return (
        <Virtuoso<PeerStatus, PeerRowContext>
            ref={virtuosoRef}
            data={data}
            customScrollParent={scrollParent}
            increaseViewportBy={400}
            computeItemKey={(_, peer) => peer.pubKey}
            components={{ Header: ListTopSpacer }}
            context={ctx}
            itemContent={renderPeerRow}
        />
    );
};

type PeerRowContext = {
    onKeyDown: (e: KeyboardEvent<Element>, index: number) => void;
    onSelect: (peer: PeerStatus) => void;
    setRowRef: (pubKey: string, el: HTMLButtonElement | null) => void;
    dropTarget: string | null;
    onDropTarget: (pubKey: string | null) => void;
};

const renderPeerRow = (index: number, peer: PeerStatus, ctx: PeerRowContext): ReactNode => (
    <PeerRow
        peer={peer}
        index={index}
        onKeyDown={ctx.onKeyDown}
        onSelect={ctx.onSelect}
        setRowRef={ctx.setRowRef}
        isDropTarget={ctx.dropTarget === peer.pubKey}
        onDropTarget={ctx.onDropTarget}
    />
);

type PeerRowProps = {
    peer: PeerStatus;
    index: number;
    onKeyDown: (e: KeyboardEvent<Element>, index: number) => void;
    onSelect: (peer: PeerStatus) => void;
    setRowRef: (pubKey: string, el: HTMLButtonElement | null) => void;
    isDropTarget: boolean;
    onDropTarget: (pubKey: string | null) => void;
};

const PeerRow = ({
    peer,
    index,
    onKeyDown,
    onSelect,
    setRowRef,
    isDropTarget,
    onDropTarget,
}: PeerRowProps) => {
    const { t } = useTranslation();
    const isConnected = peer.connStatus === "Connected";
    const peerName = shortenDns(peer.fqdn) || peer.ip;
    const statusLabel = t(peerStatusLabelKey(peer.connStatus));
    const handleKey = (e: KeyboardEvent<Element>) => onKeyDown(e, index);
    return (
        <div
            onDragOver={(e: DragEvent) => {
                if (!isConnected) return;
                e.preventDefault();
                onDropTarget(peer.pubKey);
            }}
            className={cn(
                "group relative flex min-w-0 items-start gap-2.5 py-3 pl-6 pr-4",
                "transition-colors hover:bg-nb-gray-900/40",
                "wails-no-draggable",
            )}
        >
            {isDropTarget && (
                <div
                    className={cn(
                        "pointer-events-none absolute inset-x-2 inset-y-0.5 z-10",
                        "flex items-center justify-center gap-2 rounded-lg",
                        "border border-netbird bg-nb-gray-940/90 text-netbird",
                    )}
                >
                    <SendIcon size={14} aria-hidden={"true"} />
                    <span className={"text-sm"}>{t("peers.dropToSend")}</span>
                </div>
            )}
            <button
                type={"button"}
                tabIndex={0}
                ref={(el) => setRowRef(peer.pubKey, el)}
                aria-label={t("peers.row.label", { name: peerName, status: statusLabel })}
                onClick={() => onSelect(peer)}
                onKeyDown={handleKey}
                className={cn(
                    "absolute inset-0 cursor-default outline-none",
                    "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
                )}
            />
            <Tooltip content={statusLabel} side={"left"}>
                <span
                    aria-hidden={"true"}
                    className={cn(
                        "relative mt-2 h-2 w-2 shrink-0 rounded-full",
                        dotClass(peer.connStatus),
                    )}
                />
            </Tooltip>
            <div
                className={
                    "pointer-events-none relative flex min-w-0 flex-1 flex-col leading-tight"
                }
            >
                <div>
                    <CopyToClipboard
                        message={peer.fqdn}
                        className={"pointer-events-auto"}
                        onKeyDown={handleKey}
                    >
                        <TruncatedText
                            text={shortenDns(peer.fqdn)}
                            className={
                                "block max-w-[300px] truncate text-[0.81rem] font-medium text-nb-gray-100"
                            }
                        />
                    </CopyToClipboard>
                </div>
                <div>
                    <CopyToClipboard
                        message={peer.ip}
                        className={"pointer-events-auto"}
                        onKeyDown={handleKey}
                    >
                        <span className={"truncate font-mono text-xs text-nb-gray-400"}>
                            {peer.ip}
                        </span>
                    </CopyToClipboard>
                </div>
            </div>
            {isConnected && peer.latencyMs > 0 && (
                <span
                    className={cn(
                        "pointer-events-none relative shrink-0 self-center text-xs tabular-nums",
                        latencyColor(peer.latencyMs),
                    )}
                >
                    {peer.latencyMs} ms
                </span>
            )}
            <ChevronRightIcon
                size={16}
                aria-hidden={"true"}
                className={cn(
                    "pointer-events-none relative shrink-0 self-center text-nb-gray-300",
                    "opacity-0 transition-opacity group-hover:opacity-100",
                )}
            />
        </div>
    );
};
