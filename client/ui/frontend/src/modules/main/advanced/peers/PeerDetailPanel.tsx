import {
    type ComponentType,
    Fragment,
    type KeyboardEvent as ReactKeyboardEvent,
    type ReactNode,
    useCallback,
    useEffect,
    useRef,
    useState,
} from "react";
import { useTranslation } from "react-i18next";
import { AnimatePresence, motion, type Transition } from "framer-motion";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import {
    ArrowDownIcon,
    ArrowLeftIcon,
    ArrowUpDownIcon,
    ArrowUpIcon,
    Check as CheckIcon,
    ChevronDownIcon,
    ChevronsLeftRightEllipsisIcon,
    ClockIcon,
    Copy as CopyIcon,
    GaugeIcon,
    HandshakeIcon,
    KeyRoundIcon,
    Layers3Icon,
    type LucideProps,
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
import { formatBytes, formatRelative, latencyColor, shortenDns } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { usePeerDetail } from "@/contexts/PeerDetailContext";
import { useFocusVisible } from "@/hooks/useFocusVisible";
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

    // Daemon updates latency/bytes/handshake without pushing a fresh status
    // snapshot, so tick locally to keep relative timestamps live.
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
        const MIN_SPIN_MS = 600;
        const minDelay = new Promise<void>((r) => setTimeout(r, MIN_SPIN_MS));
        try {
            await Promise.all([refresh(), minDelay]);
        } finally {
            setRefreshing(false);
        }
    }, [refresh, refreshing]);

    useEffect(() => {
        if (!selected) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") {
                setSelected(null);
                return;
            }
            if (e.key === "ArrowLeft") {
                const target = e.target as HTMLElement | null;
                const tag = target?.tagName;
                if (tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable) return;
                setSelected(null);
            }
        };
        globalThis.addEventListener("keydown", onKey);
        return () => globalThis.removeEventListener("keydown", onKey);
    }, [selected, setSelected]);

    const dialogRef = useRef<HTMLDivElement>(null);
    const backButtonRef = useRef<HTMLButtonElement>(null);

    useEffect(() => {
        if (!selected) return;
        // Defer focus until the slide-in animation has started rendering.
        // preventScroll avoids the browser scrolling the parent to chase the
        // still-offscreen button, which lands as a stutter at the end of the slide.
        requestAnimationFrame(() => backButtonRef.current?.focus({ preventScroll: true }));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [selected?.pubKey]);

    const getFocusable = (): HTMLElement[] => {
        const root = dialogRef.current;
        if (!root) return [];
        const sel =
            "button:not([disabled]), [href], input:not([disabled]), select:not([disabled])," +
            ' textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
        return Array.from(root.querySelectorAll<HTMLElement>(sel)).filter(
            (el) => el.offsetParent !== null || el === document.activeElement,
        );
    };

    const onDialogKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
        if (e.key !== "Tab") return;
        const focusables = getFocusable();
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey) {
            if (active === first || !active || !dialogRef.current?.contains(active)) {
                e.preventDefault();
                last.focus();
            }
        } else if (active === last) {
            e.preventDefault();
            first.focus();
        }
    };

    return (
        <AnimatePresence>
            {selected && (
                <motion.div
                    ref={dialogRef}
                    role={"dialog"}
                    aria-modal={"true"}
                    aria-labelledby={"nb-peer-detail-title"}
                    onKeyDown={onDialogKeyDown}
                    initial={{ x: "100%" }}
                    animate={{ x: 0 }}
                    exit={{ x: "100%" }}
                    transition={transition}
                    style={{ willChange: "transform" }}
                    className={cn("absolute inset-0 z-20 flex flex-col", "bg-nb-gray-940")}
                >
                    <div
                        className={cn(
                            "flex shrink-0 items-center gap-3",
                            "h-12 border-b border-nb-gray-910 px-3",
                        )}
                    >
                        <button
                            ref={backButtonRef}
                            type={"button"}
                            tabIndex={0}
                            onClick={() => setSelected(null)}
                            aria-label={t("common.close")}
                            className={cn(
                                "flex h-8 w-8 shrink-0 items-center justify-center rounded-md",
                                "text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100",
                                "cursor-default outline-none transition-colors",
                                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                                "wails-no-draggable",
                            )}
                        >
                            <ArrowLeftIcon size={16} aria-hidden={"true"} />
                        </button>
                        <Tooltip content={t(peerStatusLabelKey(selected.connStatus))} side={"top"}>
                            <span
                                aria-hidden={"true"}
                                className={cn(
                                    "h-2 w-2 shrink-0 rounded-full",
                                    dotClass(selected.connStatus),
                                )}
                            />
                        </Tooltip>
                        <CopyToClipboard
                            message={selected.fqdn || selected.ip}
                            size={11}
                            className={"min-w-0 flex-1"}
                            iconClassName={"top-[2px]"}
                        >
                            <span
                                id={"nb-peer-detail-title"}
                                className={"truncate text-sm font-medium text-nb-gray-100"}
                            >
                                {shortenDns(selected.fqdn) || selected.ip}
                            </span>
                        </CopyToClipboard>
                        <Tooltip content={t("peers.details.refresh")}>
                            <button
                                type={"button"}
                                tabIndex={0}
                                onClick={onRefresh}
                                disabled={refreshing}
                                aria-label={t("peers.details.refresh")}
                                aria-busy={refreshing}
                                className={cn(
                                    "flex h-8 w-8 shrink-0 items-center justify-center rounded-md",
                                    "text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100",
                                    "cursor-default outline-none transition-colors",
                                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                                    "wails-no-draggable",
                                    "disabled:opacity-50 disabled:hover:bg-transparent",
                                )}
                            >
                                <RefreshCwIcon
                                    size={14}
                                    aria-hidden={"true"}
                                    className={refreshing ? "animate-spin" : undefined}
                                />
                            </button>
                        </Tooltip>
                    </div>
                    <ScrollArea.Root type={"auto"} className={"min-h-0 flex-1 overflow-hidden"}>
                        <ScrollArea.Viewport className={"h-full w-full"}>
                            <PeerDetails peer={selected} now={now} />
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
            {peer.ipv6 && (
                <Row icon={MapPinIcon} label={t("peers.details.netbirdIpv6")}>
                    <CopyToClipboard
                        message={peer.ipv6}
                        alwaysShowIcon
                        className={"min-w-0 max-w-full"}
                        iconClassName={"top-0"}
                    >
                        <TruncatedRowValue value={peer.ipv6} mono />
                    </CopyToClipboard>
                </Row>
            )}
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
                            className={"min-w-0 max-w-full"}
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
                            "flex items-center justify-end gap-3 font-medium text-nb-gray-300"
                        }
                    >
                        <div className={"flex items-center gap-1.5 whitespace-nowrap"}>
                            <ArrowDownIcon
                                size={13}
                                aria-hidden={"true"}
                                className={"text-sky-400"}
                            />
                            <span className={"sr-only"}>{t("peers.details.bytesReceived")}:</span>
                            <span className={"tabular-nums"}>{formatBytes(peer.bytesRx)}</span>
                        </div>
                        <div className={"flex items-center gap-1.5 whitespace-nowrap"}>
                            <ArrowUpIcon
                                size={13}
                                aria-hidden={"true"}
                                className={"text-netbird"}
                            />
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
                        className={"min-w-0 max-w-full"}
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
                    className={"min-w-0 max-w-full"}
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
                    tabIndex={0}
                    aria-haspopup={"dialog"}
                    aria-expanded={open}
                    className={cn(
                        "inline-flex shrink-0 items-center gap-1 rounded",
                        "bg-nb-gray-930 hover:bg-nb-gray-910/80 data-[state=open]:bg-nb-gray-910",
                        "border border-nb-gray-900",
                        "py-1 pl-2.5 pr-2 text-xs font-medium text-nb-gray-300",
                        "wails-no-draggable cursor-default outline-none transition-all",
                        "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                    )}
                >
                    {networks.length}
                    <ChevronDownIcon
                        size={12}
                        aria-hidden={"true"}
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
                        "z-50 max-h-72 min-w-64 max-w-[280px] overflow-auto",
                        "rounded-lg border border-nb-gray-900 bg-nb-gray-935",
                        "p-1 text-nb-gray-200 shadow-lg outline-none",
                        "flex flex-col",
                    )}
                >
                    {networks.map((n, i) => (
                        <Fragment key={n}>
                            {i > 0 && <div className={"-mx-1 my-1 h-px bg-nb-gray-910"} />}
                            <ResourceRow value={n} />
                        </Fragment>
                    ))}
                </Popover.Content>
            </Popover.Portal>
        </Popover.Root>
    );
};

const ResourceRow = ({ value }: { value: string }) => {
    const { t } = useTranslation();
    const [copied, setCopied] = useState(false);
    const isFocusVisible = useFocusVisible();
    const handleClick = async () => {
        if (!value) return;
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 500);
        } catch (e) {
            console.warn("copy resource to clipboard failed", e);
        }
    };
    return (
        <button
            type={"button"}
            onClick={handleClick}
            tabIndex={0}
            aria-label={`${t("common.copy")} ${value}`}
            className={cn(
                "group/resourcerow relative flex items-center justify-between gap-3",
                "rounded-md px-2 py-1.5 text-left",
                "text-nb-gray-200 hover:bg-nb-gray-900 hover:text-nb-gray-50",
                "cursor-default outline-none transition-colors",
                isFocusVisible &&
                    "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
            )}
        >
            <span className={"min-w-0 truncate font-mono text-[0.75rem]"}>{value}</span>
            <span
                aria-hidden={"true"}
                className={"inline-flex shrink-0 items-center text-nb-gray-200"}
            >
                {copied ? <CheckIcon size={11} /> : <CopyIcon size={11} />}
            </span>
        </button>
    );
};

const TruncatedRowValue = ({ value, mono }: { value: string; mono?: boolean }) => (
    <TruncatedText
        text={value}
        className={cn(
            "inline-block min-w-0 max-w-[260px] truncate align-middle",
            mono && "font-mono",
        )}
    />
);

const Row = ({ icon: Icon, iconClassName, label, children }: RowProps) => (
    <li className={"flex min-w-0 items-center gap-2 px-5 py-4 text-xs text-nb-gray-100"}>
        <Icon
            size={14}
            aria-hidden={"true"}
            className={cn("shrink-0 text-nb-gray-100", iconClassName)}
        />
        <span className={"shrink-0 font-semibold text-nb-gray-200"}>{label}</span>
        <span
            className={cn(
                "min-w-0 flex-1 pl-8 text-right",
                "font-medium text-nb-gray-350",
                "flex items-center justify-end",
            )}
        >
            {children}
        </span>
    </li>
);
