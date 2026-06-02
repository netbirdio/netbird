import { ComponentType, ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AnimatePresence, motion, type Transition } from "framer-motion";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import {
    ArrowDownIcon,
    ArrowLeftIcon,
    ArrowUpDownIcon,
    ArrowUpIcon,
    ChevronDownIcon,
    ChevronsLeftRightEllipsisIcon,
    ClockIcon,
    GaugeIcon,
    HandshakeIcon,
    KeyRoundIcon,
    Layers3Icon,
    LucideProps,
    MapPinIcon,
    MonitorIcon,
    Radio,
    RefreshCwIcon,
    WaypointsIcon,
} from "lucide-react";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { Tooltip } from "@/components/Tooltip";
import { TruncatedText } from "@/components/TruncatedText";
import { formatBytes, formatRelative, latencyColor } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { usePeerDetail } from "@/contexts/PeerDetailContext";
import { mockOr, mockPeers } from "@/lib/mock";
import { peerStatusLabelKey } from "./Peers";

const DEFAULT_TRANSITION: Transition = {
    duration: 0.32,
    ease: [0.32, 0.72, 0, 1],
};

const DASH = "-";

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

type Props = {
    transition?: Transition;
};

export const PeerDetailPanel = ({ transition = DEFAULT_TRANSITION }: Props) => {
    const { t } = useTranslation();
    const { selected, setSelected } = usePeerDetail();
    const { status, refresh } = useStatus();

    // Keep `selected` in sync with the live peer list so the panel reflects
    // status / latency / byte updates without re-opening. If the peer
    // disappears, close the panel.
    useEffect(() => {
        if (!selected) return;
        const peers = mockOr(status?.peers ?? [], mockPeers);
        const fresh = peers.find((p) => p.pubKey === selected.pubKey);
        if (!fresh) {
            setSelected(null);
            return;
        }
        if (fresh !== selected) setSelected(fresh);
    }, [status, selected, setSelected]);

    // Re-render every second so the relative timestamps in PeerDetails
    // ("Xs ago", "Xm ago") tick. The daemon updates latency/bytes/handshake
    // silently without pushing a fresh status snapshot — see
    // status.go UpdateLatency / UpdateWireGuardPeerState — so without this
    // the displayed age would freeze for a stably-Connected peer.
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        if (!selected) return;
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, [selected]);

    const [refreshing, setRefreshing] = useState(false);
    const onRefresh = useCallback(async () => {
        if (refreshing) return;
        setRefreshing(true);
        // Refresh over the unix socket usually completes in <50ms, faster
        // than the spin animation can show. Hold the spinning state for at
        // least one full rotation so the click feels responsive.
        const MIN_SPIN_MS = 600;
        const minDelay = new Promise<void>((r) => setTimeout(r, MIN_SPIN_MS));
        try {
            await Promise.all([refresh(), minDelay]);
        } finally {
            setRefreshing(false);
        }
    }, [refresh, refreshing]);

    // Esc closes the panel.
    useEffect(() => {
        if (!selected) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") setSelected(null);
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [selected, setSelected]);

    return (
        <AnimatePresence>
            {selected && (
                <motion.div
                    initial={{ x: "100%" }}
                    animate={{ x: 0 }}
                    exit={{ x: "100%" }}
                    transition={transition}
                    className={cn("absolute inset-0 z-20 flex flex-col", "bg-nb-gray-940")}
                >
                    <div
                        className={cn(
                            "shrink-0 flex items-center gap-3",
                            "px-3 h-12 border-b border-nb-gray-910",
                        )}
                    >
                        <button
                            type={"button"}
                            onClick={() => setSelected(null)}
                            aria-label={t("common.close")}
                            className={cn(
                                "shrink-0 h-8 w-8 rounded-md flex items-center justify-center",
                                "text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100",
                                "transition-colors outline-none cursor-default",
                                "wails-no-draggable",
                            )}
                        >
                            <ArrowLeftIcon size={16} />
                        </button>
                        <Tooltip content={t(peerStatusLabelKey(selected.connStatus))} side={"top"}>
                            <span
                                className={cn(
                                    "h-2 w-2 rounded-full shrink-0",
                                    dotClass(selected.connStatus),
                                )}
                            />
                        </Tooltip>
                        <CopyToClipboard
                            message={selected.fqdn || selected.ip}
                            size={11}
                            className={"flex-1 min-w-0"}
                            iconClassName={"top-[2px]"}
                        >
                            <span className={"text-sm font-medium text-nb-gray-100 truncate"}>
                                {selected.fqdn || selected.ip}
                            </span>
                        </CopyToClipboard>
                        <Tooltip content={t("peers.details.refresh")}>
                            <button
                                type={"button"}
                                onClick={onRefresh}
                                disabled={refreshing}
                                aria-label={t("peers.details.refresh")}
                                className={cn(
                                    "shrink-0 h-8 w-8 rounded-md flex items-center justify-center",
                                    "text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100",
                                    "transition-colors outline-none cursor-default",
                                    "wails-no-draggable",
                                    "disabled:opacity-50 disabled:hover:bg-transparent",
                                )}
                            >
                                <RefreshCwIcon
                                    size={14}
                                    className={refreshing ? "animate-spin" : undefined}
                                />
                            </button>
                        </Tooltip>
                    </div>
                    <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                        <ScrollArea.Viewport className={"h-full w-full"}>
                            <PeerDetails peer={selected} now={now} />
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
                </motion.div>
            )}
        </AnimatePresence>
    );
};

const PeerDetails = ({ peer, now }: { peer: PeerStatus; now: number }) => {
    const { t } = useTranslation();
    const formatAge = (unix: number, fallback: string): string => {
        if (!Number.isFinite(unix) || unix <= 0) return fallback;
        const diff = Math.floor(now / 1000 - unix);
        if (diff < 1) return t("peers.details.justNow");
        return formatRelative(unix, now) ?? fallback;
    };
    const lastHandshake = formatAge(peer.lastHandshakeUnix, t("peers.details.never"));
    const statusSince = formatAge(peer.connStatusUpdateUnix, DASH);
    const isConnected = peer.connStatus === "Connected";
    const connectionLabel = peer.relayed ? t("peers.details.relayed") : t("peers.details.p2p");

    return (
        <ul className={"flex flex-col divide-y divide-nb-gray-920"}>
            <Row icon={MapPinIcon} label={t("peers.details.netbirdIp")}>
                {peer.ip ? (
                    <CopyToClipboard
                        message={peer.ip}
                        alwaysShowIcon
                        className={"max-w-full"}
                        iconClassName={"top-0"}
                    >
                        <span className={"font-mono"}>{peer.ip}</span>
                    </CopyToClipboard>
                ) : (
                    DASH
                )}
            </Row>
            {isConnected && (
                <Row icon={ChevronsLeftRightEllipsisIcon} label={t("peers.details.connection")}>
                    <span className={"whitespace-nowrap"}>{connectionLabel}</span>
                </Row>
            )}
            {peer.relayed && (
                <Row icon={WaypointsIcon} label={t("peers.details.relayAddress")}>
                    {peer.relayAddress ? (
                        <CopyToClipboard
                            message={peer.relayAddress}
                            alwaysShowIcon
                            className={"max-w-full min-w-0"}
                            iconClassName={"top-0"}
                        >
                            <TruncatedRowValue value={peer.relayAddress} mono />
                        </CopyToClipboard>
                    ) : (
                        DASH
                    )}
                </Row>
            )}
            {peer.latencyMs > 0 && (
                <Row icon={GaugeIcon} label={t("peers.details.latency")}>
                    <span className={cn("tabular-nums", latencyColor(peer.latencyMs))}>
                        {peer.latencyMs} ms
                    </span>
                </Row>
            )}
            {(peer.bytesRx > 0 || peer.bytesTx > 0) && (
                <Row icon={ArrowUpDownIcon} label={t("peers.details.bytes")}>
                    <div
                        className={
                            "flex items-center gap-3 justify-end text-nb-gray-300 font-medium"
                        }
                    >
                        <div className={"flex gap-1.5 items-center whitespace-nowrap"}>
                            <ArrowDownIcon size={13} className={"text-sky-400"} />
                            <span className={"sr-only"}>{t("peers.details.bytesReceived")}:</span>
                            <span className={"tabular-nums"}>{formatBytes(peer.bytesRx)}</span>
                        </div>
                        <div className={"flex gap-1.5 items-center whitespace-nowrap"}>
                            <ArrowUpIcon size={13} className={"text-netbird"} />
                            <span className={"sr-only"}>{t("peers.details.bytesSent")}:</span>
                            <span className={"tabular-nums"}>{formatBytes(peer.bytesTx)}</span>
                        </div>
                    </div>
                </Row>
            )}
            <Row icon={HandshakeIcon} label={t("peers.details.lastHandshake")}>
                {lastHandshake}
            </Row>
            <Row icon={ClockIcon} label={t("peers.details.statusSince")}>
                {statusSince}
            </Row>
            {peer.networks.length > 0 && (
                <Row icon={Layers3Icon} label={t("peers.details.networks")}>
                    <ResourcesValue networks={peer.networks} />
                </Row>
            )}
            <IceRow
                icon={MonitorIcon}
                baseLabel={t("peers.details.localIce")}
                type={peer.localIceCandidateType}
                endpoint={peer.localIceCandidateEndpoint}
            />
            <IceRow
                icon={Radio}
                baseLabel={t("peers.details.remoteIce")}
                type={peer.remoteIceCandidateType}
                endpoint={peer.remoteIceCandidateEndpoint}
            />
            <Row icon={KeyRoundIcon} label={t("peers.details.publicKey")}>
                {peer.pubKey ? (
                    <CopyToClipboard
                        message={peer.pubKey}
                        alwaysShowIcon
                        className={"max-w-full min-w-0"}
                        iconClassName={"top-0"}
                    >
                        <TruncatedRowValue value={peer.pubKey} mono />
                    </CopyToClipboard>
                ) : (
                    DASH
                )}
            </Row>
        </ul>
    );
};

type RowProps = {
    icon: ComponentType<LucideProps>;
    iconClassName?: string;
    label: string;
    children: ReactNode;
};

type IceRowProps = {
    icon: ComponentType<LucideProps>;
    baseLabel: string;
    type: string;
    endpoint: string;
};

const capitalize = (s: string): string => (s ? s[0].toUpperCase() + s.slice(1) : s);

const IceRow = ({ icon, baseLabel, type, endpoint }: IceRowProps) => {
    if (!type && !endpoint) return null;
    const label = type ? `${baseLabel} (${capitalize(type)})` : baseLabel;
    return (
        <Row icon={icon} label={label}>
            {endpoint ? (
                <CopyToClipboard
                    message={endpoint}
                    alwaysShowIcon
                    className={"max-w-full min-w-0"}
                    iconClassName={"top-0"}
                >
                    <TruncatedRowValue value={endpoint} mono />
                </CopyToClipboard>
            ) : (
                <span className={"truncate"}>{capitalize(type)}</span>
            )}
        </Row>
    );
};

// Single "View {n}" badge with a chevron that opens a click popover listing
// each routed resource on its own line with a click-to-copy entry. Avoids
// the repetitive "first item + N more" pattern given the row already has a
// "Resources" label and Layers icon.
const ResourcesValue = ({ networks }: { networks: string[] }) => (
    <ResourcesPopover networks={networks} />
);

const ResourcesPopover = ({ networks }: { networks: string[] }) => {
    const [open, setOpen] = useState(false);

    return (
        <Popover.Root open={open} onOpenChange={setOpen}>
            <Popover.Trigger asChild>
                <button
                    type={"button"}
                    className={cn(
                        "shrink-0 inline-flex items-center gap-1 rounded",
                        "bg-nb-gray-930 hover:bg-nb-gray-910/80 data-[state=open]:bg-nb-gray-910",
                        "border border-nb-gray-900",
                        "px-2 py-1 text-xs font-medium text-nb-gray-300",
                        "wails-no-draggable cursor-default outline-none transition-all",
                    )}
                >
                    {networks.length}
                    <ChevronDownIcon
                        size={12}
                        className={cn("transition-transform duration-150", open && "rotate-180")}
                    />
                </button>
            </Popover.Trigger>
            <Popover.Portal>
                <Popover.Content
                    side={"bottom"}
                    align={"end"}
                    sideOffset={6}
                    onOpenAutoFocus={(e) => e.preventDefault()}
                    className={cn(
                        "z-50 max-w-[18rem] max-h-72 overflow-auto",
                        "rounded-lg border border-nb-gray-900 bg-nb-gray-935",
                        "p-2 pr-4 shadow-lg outline-none",
                    )}
                >
                    <ul className={"flex flex-col"}>
                        {networks.map((n) => (
                            <li key={n}>
                                <CopyToClipboard message={n} className={"px-1 py-0.5"}>
                                    <span
                                        className={
                                            "font-mono text-[0.72rem] text-nb-gray-200 whitespace-nowrap"
                                        }
                                    >
                                        {n}
                                    </span>
                                </CopyToClipboard>
                            </li>
                        ))}
                    </ul>
                </Popover.Content>
            </Popover.Portal>
        </Popover.Root>
    );
};

const TruncatedRowValue = ({ value, mono }: { value: string; mono?: boolean }) => (
    <TruncatedText
        text={value}
        className={cn(
            "inline-block truncate align-middle min-w-0 max-w-[260px]",
            mono && "font-mono",
        )}
    />
);

const Row = ({ icon: Icon, iconClassName, label, children }: RowProps) => (
    <li className={"flex items-center gap-2 px-5 py-4 text-xs text-nb-gray-100 min-w-0"}>
        <Icon size={14} className={cn("text-nb-gray-100 shrink-0", iconClassName)} />
        <span className={"text-nb-gray-200 shrink-0 font-semibold"}>{label}</span>
        <span
            className={cn(
                "min-w-0 flex-1 text-right pl-8",
                "text-nb-gray-350 font-medium",
                "flex justify-end items-center",
            )}
        >
            {children}
        </span>
    </li>
);
