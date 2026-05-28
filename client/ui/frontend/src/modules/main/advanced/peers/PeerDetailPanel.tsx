import { ComponentType, ReactNode, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { AnimatePresence, motion, type Transition } from "framer-motion";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import {
    ArrowDownIcon,
    ArrowLeftIcon,
    ArrowUpDownIcon,
    ArrowUpIcon,
    CableIcon,
    ClockIcon,
    GaugeIcon,
    HandshakeIcon,
    KeyRoundIcon,
    Layers3Icon,
    LucideProps,
    MapPinIcon,
    MonitorIcon,
    NetworkIcon,
    Radio,
    ZapIcon,
} from "lucide-react";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { formatBytes, formatRelative, latencyColor } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { usePeerDetail } from "@/contexts/PeerDetailContext";

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
    const { status } = useStatus();

    // Keep `selected` in sync with the live peer list so the panel reflects
    // status / latency / byte updates without re-opening. If the peer
    // disappears, close the panel.
    useEffect(() => {
        if (!selected) return;
        const peers = status?.peers ?? [];
        const fresh = peers.find((p) => p.pubKey === selected.pubKey);
        if (!fresh) {
            setSelected(null);
            return;
        }
        if (fresh !== selected) setSelected(fresh);
    }, [status, selected, setSelected]);

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
                        <span
                            className={cn(
                                "h-2 w-2 rounded-full shrink-0",
                                dotClass(selected.connStatus),
                            )}
                            title={selected.connStatus}
                        />
                        <span className={"min-w-0 text-sm font-medium text-nb-gray-100 truncate"}>
                            {selected.fqdn || selected.ip}
                        </span>
                    </div>
                    <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                        <ScrollArea.Viewport className={"h-full w-full"}>
                            <PeerDetails peer={selected} />
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

const PeerDetails = ({ peer }: { peer: PeerStatus }) => {
    const { t } = useTranslation();
    const lastHandshake = formatRelative(peer.lastHandshakeUnix) ?? t("peers.details.never");
    const statusSince = formatRelative(peer.connStatusUpdateUnix) ?? DASH;
    const isConnected = peer.connStatus === "Connected";
    const ConnectionIcon = peer.relayed ? NetworkIcon : ZapIcon;
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
                <Row icon={CableIcon} label={t("peers.details.connection")}>
                    <span className={"inline-flex items-center gap-1.5 whitespace-nowrap"}>
                        <ConnectionIcon size={13} />
                        {connectionLabel}
                    </span>
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
            {peer.relayed && (
                <Row icon={NetworkIcon} label={t("peers.details.relayAddress")}>
                    {peer.relayAddress ? (
                        <CopyToClipboard
                            message={peer.relayAddress}
                            alwaysShowIcon
                            className={"max-w-full"}
                            iconClassName={"top-0"}
                        >
                            <span className={"font-mono truncate"}>{peer.relayAddress}</span>
                        </CopyToClipboard>
                    ) : (
                        DASH
                    )}
                </Row>
            )}
            {peer.networks.length > 0 && (
                <Row icon={Layers3Icon} label={t("peers.details.networks")}>
                    <span className={"break-words"}>{peer.networks.join(", ")}</span>
                </Row>
            )}
            <Row icon={KeyRoundIcon} label={t("peers.details.publicKey")}>
                {peer.pubKey ? (
                    <CopyToClipboard
                        message={peer.pubKey}
                        alwaysShowIcon
                        className={"max-w-full"}
                        iconClassName={"top-0"}
                    >
                        <span className={"font-mono truncate"}>{peer.pubKey}</span>
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
                    className={"max-w-full"}
                    iconClassName={"top-0"}
                >
                    <span className={"font-mono truncate"}>{endpoint}</span>
                </CopyToClipboard>
            ) : (
                <span className={"truncate"}>{capitalize(type)}</span>
            )}
        </Row>
    );
};

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
