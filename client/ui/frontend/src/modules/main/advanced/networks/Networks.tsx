import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
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
import { NetworkFilter, NetworkFilters } from "./NetworkFilters";

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
        <div className={"flex flex-col w-full h-full min-h-0"}>
            <div className={"flex items-center gap-2 px-6 py-2.5 border-b border-nb-gray-910"}>
                <div className={"flex-1 min-w-0"}>
                    <SearchInput
                        ref={searchRef}
                        placeholder={t("networks.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <NetworkFilters value={filter} onChange={setFilter} counts={counts} />
            </div>
            <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                <ScrollArea.Viewport className={"h-full w-full"}>
                    {filtered.length === 0 ? (
                        <NoResults />
                    ) : (
                        <NetworksList data={filtered} onToggle={toggleNetwork} />
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
            {filtered.length > 0 && (
                <div
                    className={cn(
                        "flex items-center gap-3 px-6 py-3.5",
                        "border-t border-nb-gray-910",
                    )}
                >
                    <span className={"flex-1 text-xs font-medium text-nb-gray-300 tabular-nums"}>
                        {t("networks.bulk.selectionCount", {
                            selected: selectedInView,
                            total: filtered.length,
                        })}
                    </span>
                    <button
                        type={"button"}
                        onClick={onBulkClick}
                        className={cn(
                            "inline-flex items-center h-8 px-3 rounded-md",
                            "text-xs font-medium text-nb-gray-100",
                            "bg-nb-gray-920 hover:bg-nb-gray-910 border border-nb-gray-900 hover:border-nb-gray-850",
                            "transition-colors outline-none wails-no-draggable cursor-pointer",
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
};

const NetworksList = ({ data, onToggle }: NetworksListProps) => {
    const { t } = useTranslation();

    return (
        <ul className={"flex flex-col"}>
            {data.map((n) => (
                <li
                    key={n.id}
                    className={cn(
                        "group relative flex items-start gap-2.5 pl-6 pr-9 py-3 min-w-0 first:mt-2",
                        "hover:bg-nb-gray-900/40 transition-colors",
                        "wails-no-draggable",
                    )}
                >
                    <button
                        type={"button"}
                        aria-label={n.id}
                        onClick={() => onToggle(n.id, n.selected)}
                        className={"absolute inset-0 cursor-pointer"}
                    />
                    <ResourceIconBadge type={resourceTypeOf(n)} />
                    <div
                        className={
                            "min-w-0 flex-1 flex flex-col leading-tight relative pointer-events-none"
                        }
                    >
                        <div>
                            <CopyToClipboard message={n.id}>
                                <TruncatedText
                                    text={n.id}
                                    className={
                                        "block text-[0.81rem] font-medium text-nb-gray-100 truncate max-w-[300px]"
                                    }
                                />
                            </CopyToClipboard>
                        </div>
                        <Subtitle network={n} />
                    </div>
                    <div className={"shrink-0 self-center relative"}>
                        <NetworkToggle
                            checked={n.selected}
                            onChange={() => onToggle(n.id, n.selected)}
                            label={n.selected ? t("networks.selected") : t("networks.unselected")}
                        />
                    </div>
                </li>
            ))}
        </ul>
    );
};

const ResourceIconBadge = ({ type }: { type: ResourceType }) => {
    const Icon = resourceIconFor(type);
    return (
        <div
            className={cn(
                "h-9 w-9 shrink-0 rounded-md flex items-center justify-center mt-[0.25rem]",
                "bg-nb-gray-920 border border-nb-gray-900 text-nb-gray-300",
            )}
        >
            <Icon size={14} />
        </div>
    );
};

const Subtitle = ({ network }: { network: Network }) => {
    if (isDnsRoute(network)) {
        const domain = network.domains[0];
        const ips = network.resolvedIps[domain] ?? [];
        return <DomainSubtitle domain={domain} ips={ips} />;
    }

    if (network.range && network.range !== INVALID_PREFIX) {
        return (
            <div>
                <CopyToClipboard message={network.range}>
                    <TruncatedText
                        text={network.range}
                        className={
                            "block text-xs font-mono text-nb-gray-400 truncate max-w-[300px]"
                        }
                    />
                </CopyToClipboard>
            </div>
        );
    }

    return null;
};

const DomainSubtitle = ({ domain, ips }: { domain: string; ips: string[] }) => {
    const span = (
        <span className={"block text-xs font-mono text-nb-gray-400 truncate max-w-[300px]"}>
            {domain}
        </span>
    );
    return (
        <div>
            <CopyToClipboard message={domain}>
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
                            "max-w-[18rem] max-h-72 overflow-auto",
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
                                    "font-mono text-[0.72rem] text-nb-gray-100 whitespace-nowrap"
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
    onChange: () => void;
    label: string;
    mixed?: boolean;
};

const NetworkToggle = ({ checked, onChange, label, mixed }: ToggleProps) => {
    const checkedTranslate = checked ? "translate-x-[1.125rem]" : "translate-x-0.5";
    return (
        <button
            type={"button"}
            role={"switch"}
            aria-checked={mixed ? "mixed" : checked}
            aria-label={label}
            onClick={onChange}
            className={cn(
                "shrink-0 inline-flex h-5 w-9 items-center rounded-full",
                "transition-colors cursor-pointer wails-no-draggable",
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
        </button>
    );
};
