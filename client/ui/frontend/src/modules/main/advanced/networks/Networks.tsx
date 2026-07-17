import {
    type KeyboardEvent,
    useEffect,
    useMemo,
    useRef,
    useState,
    type ComponentType,
    type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Virtuoso, type VirtuosoHandle } from "react-virtuoso";
import { GlobeIcon, Layers3Icon, type LucideProps, NetworkIcon, WorkflowIcon } from "lucide-react";
import type { Network } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { reconcileOrder } from "@/lib/sorting";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { Tooltip } from "@/components/Tooltip";
import { TruncatedText } from "@/components/TruncatedText";
import { SearchInput } from "@/components/inputs/SearchInput";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { NoResults } from "@/components/empty-state/NoResults";
import { useStatus } from "@/contexts/StatusContext";
import { useNetworks } from "@/contexts/NetworksContext";
import { type NetworkFilter, NetworkFilters } from "./NetworkFilters";

// Daemon renders DNS-route prefixes (zero netip.Prefix) as "invalid Prefix".
const INVALID_PREFIX = "invalid Prefix";

const isDnsRoute = (n: Network): boolean =>
    n.domains.length > 0 && (!n.range || n.range === INVALID_PREFIX);

type ResourceType = "host" | "subnet" | "domain";

const isHostCidr = (cidr: string): boolean => {
    const [addr, bitsStr] = cidr.split("/");
    if (!addr || !bitsStr) return false;
    const bits = Number(bitsStr);
    const isV6 = addr.includes(":");
    return isV6 ? bits === 128 : bits === 32;
};

const resourceTypeOf = (n: Network): ResourceType => {
    if (isDnsRoute(n)) return "domain";
    const primary = n.range.split(",")[0].trim();
    return isHostCidr(primary) ? "host" : "subnet";
};

const resourceIconFor = (type: ResourceType): ComponentType<LucideProps> => {
    if (type === "host") return WorkflowIcon;
    if (type === "domain") return GlobeIcon;
    return NetworkIcon;
};

const buildOverlapMap = (
    routes: { id: string; range: string; domains: string[] }[],
): Map<string, string[]> => {
    const byRange = new Map<string, string[]>();
    for (const r of routes) {
        if (r.domains.length > 0) continue;
        const arr = byRange.get(r.range) ?? [];
        arr.push(r.id);
        byRange.set(r.range, arr);
    }
    const out = new Map<string, string[]>();
    for (const [range, ids] of byRange) {
        if (ids.length > 1) out.set(range, ids);
    }
    return out;
};

export const Networks = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const isConnected = status?.status === "Connected";
    const { networkRoutes, toggleNetwork, setNetworksSelected } = useNetworks();
    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState<NetworkFilter>("all");
    const [scrollParent, setScrollParent] = useState<HTMLDivElement | null>(null);
    const searchRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    const overlapGroups = useMemo(() => buildOverlapMap(networkRoutes), [networkRoutes]);

    const overlapById = useMemo(() => {
        const map = new Map<string, string[]>();
        for (const ids of overlapGroups.values()) {
            for (const id of ids) map.set(id, ids);
        }
        return map;
    }, [overlapGroups]);

    const counts = useMemo<Record<NetworkFilter, number>>(
        () => ({
            all: networkRoutes.length,
            active: networkRoutes.filter((r) => r.selected).length,
            overlapping: overlapById.size,
        }),
        [networkRoutes, overlapById],
    );

    const orderRef = useRef<string[]>([]);
    const ordered = useMemo(() => {
        const { order, items } = reconcileOrder(
            orderRef.current,
            networkRoutes,
            (r) => r.id,
            (a, b) => {
                if (a.selected !== b.selected) return a.selected ? -1 : 1;
                return a.id.localeCompare(b.id);
            },
        );
        orderRef.current = order;
        return items;
    }, [networkRoutes]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        return ordered.filter((r) => {
            if (filter === "active" && !r.selected) return false;
            if (filter === "overlapping" && !overlapById.has(r.id)) return false;
            if (q) {
                const haystack = [r.id, r.range, ...r.domains].join(" ").toLowerCase();
                if (!haystack.includes(q)) return false;
            }
            return true;
        });
    }, [ordered, search, filter, overlapById]);

    if (isConnected && networkRoutes.length === 0) {
        return (
            <EmptyState
                icon={Layers3Icon}
                title={t("networks.empty.title")}
                description={t("networks.empty.description")}
            />
        );
    }

    const selectedInView = filtered.filter((r) => r.selected).length;
    const allSelected = filtered.length > 0 && selectedInView === filtered.length;
    const bulkLabel = allSelected ? t("networks.bulk.disableAll") : t("networks.bulk.enableAll");

    const onBulkClick = () => {
        if (filtered.length === 0) return;
        if (allSelected) {
            setNetworksSelected(
                filtered.map((r) => r.id),
                false,
            ).catch((err: unknown) => console.error("disable all networks failed", err));
        } else {
            const ids = filtered.filter((r) => !r.selected).map((r) => r.id);
            setNetworksSelected(ids, true).catch((err: unknown) =>
                console.error("enable all networks failed", err),
            );
        }
    };

    return (
        <div className={"flex h-full min-h-0 w-full flex-col"}>
            <div className={"flex items-center gap-2 border-b border-nb-gray-910 px-6 py-2.5"}>
                <div className={"min-w-0 flex-1"}>
                    <SearchInput
                        ref={searchRef}
                        placeholder={t("networks.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <NetworkFilters value={filter} onChange={setFilter} counts={counts} />
            </div>
            {filtered.length === 0 ? (
                <NoResults />
            ) : (
                <ScrollArea.Root type={"auto"} className={"min-h-0 flex-1 overflow-hidden"}>
                    <ScrollArea.Viewport ref={setScrollParent} className={"h-full w-full"}>
                        {scrollParent && (
                            <NetworksList
                                data={filtered}
                                onToggle={toggleNetwork}
                                scrollParent={scrollParent}
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
            {filtered.length > 0 && (
                <div
                    className={cn(
                        "flex items-center gap-3 px-6 py-3.5",
                        "border-t border-nb-gray-910",
                    )}
                >
                    <span className={"flex-1 text-xs font-medium tabular-nums text-nb-gray-300"}>
                        {t("networks.bulk.selectionCount", {
                            selected: selectedInView,
                            total: filtered.length,
                        })}
                    </span>
                    <button
                        type={"button"}
                        tabIndex={0}
                        onClick={onBulkClick}
                        aria-label={t("networks.bulk.label")}
                        className={cn(
                            "inline-flex h-8 items-center rounded-md px-3",
                            "text-xs font-medium text-nb-gray-100",
                            "border border-nb-gray-900 bg-nb-gray-920 hover:border-nb-gray-850 hover:bg-nb-gray-910",
                            "wails-no-draggable cursor-pointer outline-none transition-colors",
                            "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                        )}
                    >
                        {bulkLabel}
                    </button>
                </div>
            )}
        </div>
    );
};

type NetworksListProps = {
    data: Network[];
    onToggle: (id: string, selected: boolean) => void;
    scrollParent: HTMLElement;
};

const NetworksHeader = () => <div className={"h-2"} />;

const NetworksList = ({ data, onToggle, scrollParent }: NetworksListProps) => {
    const virtuosoRef = useRef<VirtuosoHandle>(null);
    const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());

    const focusRow = (index: number) => {
        if (index < 0 || index >= data.length) return;
        const row = data[index];
        const tryFocus = () => {
            const el = rowRefs.current.get(row.id);
            if (el) {
                el.focus();
                return true;
            }
            return false;
        };
        if (!tryFocus()) {
            virtuosoRef.current?.scrollToIndex({ index, behavior: "auto" });
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

    const setRowRef = (id: string, el: HTMLButtonElement | null) => {
        if (el) rowRefs.current.set(id, el);
        else rowRefs.current.delete(id);
    };

    const ctx = useMemo<NetworkRowContext>(
        () => ({ onKeyDown: handleRowKeyDown, onToggle, setRowRef }),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [data, onToggle],
    );

    return (
        <Virtuoso<Network, NetworkRowContext>
            ref={virtuosoRef}
            data={data}
            customScrollParent={scrollParent}
            increaseViewportBy={400}
            computeItemKey={(_, n) => n.id}
            components={{ Header: NetworksHeader }}
            context={ctx}
            itemContent={renderNetworkRow}
        />
    );
};

type NetworkRowContext = {
    onKeyDown: (e: KeyboardEvent<Element>, index: number) => void;
    onToggle: (id: string, selected: boolean) => void;
    setRowRef: (id: string, el: HTMLButtonElement | null) => void;
};

const renderNetworkRow = (index: number, n: Network, ctx: NetworkRowContext): ReactNode => (
    <NetworkRow
        network={n}
        index={index}
        onKeyDown={ctx.onKeyDown}
        onToggle={ctx.onToggle}
        setRowRef={ctx.setRowRef}
    />
);

type NetworkRowProps = {
    network: Network;
    index: number;
    onKeyDown: (e: KeyboardEvent<Element>, index: number) => void;
    onToggle: (id: string, selected: boolean) => void;
    setRowRef: (id: string, el: HTMLButtonElement | null) => void;
};

const NetworkRow = ({ network: n, index, onKeyDown, onToggle, setRowRef }: NetworkRowProps) => {
    const { t } = useTranslation();
    // Same handler is attached to the overlay button and to the network-id copy
    // button so arrow nav works wherever focus sits inside the row.
    const handleKey = (e: KeyboardEvent<Element>) => onKeyDown(e, index);
    return (
        <div
            className={cn(
                "group relative flex min-w-0 items-start gap-2.5 py-3 pl-6 pr-9",
                "transition-colors hover:bg-nb-gray-900/40",
                "wails-no-draggable",
            )}
        >
            <button
                type={"button"}
                tabIndex={0}
                ref={(el) => setRowRef(n.id, el)}
                aria-label={t("networks.row.toggle", { name: n.id })}
                aria-pressed={n.selected}
                onClick={() => onToggle(n.id, n.selected)}
                onKeyDown={handleKey}
                className={cn(
                    "absolute inset-0 cursor-pointer outline-none",
                    "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
                )}
            />
            <ResourceIconBadge type={resourceTypeOf(n)} />
            <div
                className={
                    "pointer-events-none relative flex min-w-0 flex-1 flex-col leading-tight"
                }
            >
                <div>
                    <CopyToClipboard message={n.id} onKeyDown={handleKey}>
                        <TruncatedText
                            text={n.id}
                            className={
                                "block max-w-[300px] truncate text-[0.81rem] font-medium text-nb-gray-100"
                            }
                        />
                    </CopyToClipboard>
                </div>
                <Subtitle network={n} onKeyDown={handleKey} />
            </div>
            <div
                aria-hidden={"true"}
                className={"pointer-events-none relative shrink-0 self-center"}
            >
                <NetworkToggle checked={n.selected} />
            </div>
        </div>
    );
};

const ResourceIconBadge = ({ type }: { type: ResourceType }) => {
    const Icon = resourceIconFor(type);
    return (
        <div
            aria-hidden={"true"}
            className={cn(
                "mt-[0.25rem] flex h-9 w-9 shrink-0 items-center justify-center rounded-md",
                "border border-nb-gray-900 bg-nb-gray-920 text-nb-gray-300",
            )}
        >
            <Icon size={14} />
        </div>
    );
};

type SubtitleProps = {
    network: Network;
    onKeyDown: (e: KeyboardEvent<Element>) => void;
};

const Subtitle = ({ network, onKeyDown }: SubtitleProps) => {
    if (isDnsRoute(network)) {
        const domain = network.domains[0];
        const ips = network.resolvedIps[domain] ?? [];
        return <DomainSubtitle domain={domain} ips={ips} onKeyDown={onKeyDown} />;
    }

    if (network.range && network.range !== INVALID_PREFIX) {
        return (
            <div>
                <CopyToClipboard message={network.range} onKeyDown={onKeyDown}>
                    <TruncatedText
                        text={network.range}
                        className={
                            "block max-w-[300px] truncate font-mono text-xs text-nb-gray-400"
                        }
                    />
                </CopyToClipboard>
            </div>
        );
    }

    return null;
};

type DomainSubtitleProps = {
    domain: string;
    ips: string[];
    onKeyDown: (e: KeyboardEvent<Element>) => void;
};

const DomainSubtitle = ({ domain, ips, onKeyDown }: DomainSubtitleProps) => {
    const span = (
        <span className={"block max-w-[300px] truncate font-mono text-xs text-nb-gray-400"}>
            {domain}
        </span>
    );
    return (
        <div>
            <CopyToClipboard message={domain} onKeyDown={onKeyDown}>
                {ips.length > 0 ? (
                    <Tooltip
                        content={<ResolvedIpsTooltip ips={ips} />}
                        delayDuration={300}
                        closeDelay={300}
                        side={"right"}
                        align={"start"}
                        alignOffset={-8}
                        interactive
                        keepOpenOnClick
                        contentClassName={cn(
                            "max-h-72 max-w-[18rem] overflow-auto",
                            "rounded-lg border border-nb-gray-900 bg-nb-gray-935",
                            "p-2 pr-4",
                        )}
                    >
                        {span}
                    </Tooltip>
                ) : (
                    span
                )}
            </CopyToClipboard>
        </div>
    );
};

const ResolvedIpsTooltip = ({ ips }: { ips: string[] }) => {
    const { t } = useTranslation();
    return (
        <>
            <div className={"px-1 pb-1 text-[10px] uppercase tracking-wide text-nb-gray-300"}>
                {t("networks.ips.heading")}
            </div>
            <ul className={"flex flex-col"}>
                {ips.map((ip) => (
                    <li key={ip}>
                        <CopyToClipboard message={ip} className={"px-1 py-0.5"}>
                            <span
                                className={
                                    "whitespace-nowrap font-mono text-[0.72rem] text-nb-gray-100"
                                }
                            >
                                {ip}
                            </span>
                        </CopyToClipboard>
                    </li>
                ))}
            </ul>
        </>
    );
};

type ToggleProps = {
    checked: boolean;
    mixed?: boolean;
};

const NetworkToggle = ({ checked, mixed }: ToggleProps) => {
    const checkedTranslate = checked ? "translate-x-[1.125rem]" : "translate-x-0.5";
    return (
        <span
            className={cn(
                "inline-flex h-5 w-9 shrink-0 items-center rounded-full",
                "wails-no-draggable transition-colors",
                checked || mixed ? "bg-netbird" : "bg-nb-gray-700",
                mixed && "opacity-60",
            )}
        >
            <span
                className={cn(
                    "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                    mixed ? "translate-x-2.5" : checkedTranslate,
                )}
            />
        </span>
    );
};
