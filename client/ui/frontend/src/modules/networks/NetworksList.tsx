import type { ComponentType } from "react";
import * as Popover from "@radix-ui/react-popover";
import { GlobeIcon, type LucideProps, NetworkIcon, WorkflowIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Network } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";

// The daemon stringifies route.Network via netip.Prefix.String(). For
// DNS-based routes the prefix is the zero value, which Go renders as
// "invalid Prefix". Those rows render their domain + resolved IPs instead.
const INVALID_PREFIX = "invalid Prefix";

const isDnsRoute = (n: Network): boolean =>
    n.domains.length > 0 && (!n.range || n.range === INVALID_PREFIX);

// Mirror management's NetworkResourceType (resource.go GetResourceType):
// a CIDR is a host when its prefix length equals the address width
// (32 for IPv4, 128 for IPv6); anything broader is a subnet. Routes with
// domains attached are domain resources.
type ResourceType = "host" | "subnet" | "domain";

const isHostCidr = (cidr: string): boolean => {
    const [addr, bitsStr] = cidr.split("/");
    if (!addr || !bitsStr) return false;
    const bits = Number(bitsStr);
    // IPv6 prefixes always contain ':'; IPv4 prefixes always contain '.'.
    const isV6 = addr.includes(":");
    return isV6 ? bits === 128 : bits === 32;
};

const resourceTypeOf = (n: Network): ResourceType => {
    if (isDnsRoute(n)) return "domain";
    // n.range is a single CIDR for resource routes. Exit-node v4+v6 pairs
    // come comma-joined, but those are filtered out upstream — guard
    // defensively by inspecting only the first segment.
    const primary = n.range.split(",")[0].trim();
    return isHostCidr(primary) ? "host" : "subnet";
};

const resourceIconFor = (type: ResourceType): ComponentType<LucideProps> => {
    if (type === "host") return WorkflowIcon;
    if (type === "domain") return GlobeIcon;
    return NetworkIcon;
};

const ResourceIconBadge = ({ type }: { type: ResourceType }) => {
    const Icon = resourceIconFor(type);
    return (
        <div
            className={cn(
                "h-8 w-8 shrink-0 rounded-md flex items-center justify-center mt-[0.3125rem]",
                "bg-nb-gray-920 border border-nb-gray-900 text-nb-gray-300",
            )}
        >
            <Icon size={14} />
        </div>
    );
};

type Props = {
    data: Network[];
    onToggle: (id: string, selected: boolean) => void;
};

export const NetworksList = ({ data, onToggle }: Props) => {
    const { t } = useTranslation();

    return (
        <ul className={"flex flex-col"}>
            {data.map((n) => (
                <li
                    key={n.id}
                    onClick={() => onToggle(n.id, n.selected)}
                    className={cn(
                        "group flex items-start gap-2.5 pl-6 pr-8 py-3 min-w-0 first:mt-2",
                        "hover:bg-nb-gray-900/40 transition-colors",
                        "wails-no-draggable cursor-pointer",
                    )}
                >
                    <ResourceIconBadge type={resourceTypeOf(n)} />
                    <div className={"min-w-0 flex-1 flex flex-col leading-tight"}>
                        <div>
                            <CopyToClipboard message={n.id}>
                                <span
                                    className={
                                        "text-[0.81rem] font-medium text-nb-gray-100 truncate"
                                    }
                                >
                                    {n.id}
                                </span>
                            </CopyToClipboard>
                        </div>
                        <Subtitle network={n} />
                    </div>
                    <div
                        className={"shrink-0 self-center"}
                        onClick={(e) => e.stopPropagation()}
                    >
                        <NetworkToggle
                            checked={n.selected}
                            onChange={() => onToggle(n.id, n.selected)}
                            label={
                                n.selected
                                    ? t("networks.selected")
                                    : t("networks.unselected")
                            }
                        />
                    </div>
                </li>
            ))}
        </ul>
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
                    <span className={"text-xs font-mono text-nb-gray-400 truncate"}>
                        {network.range}
                    </span>
                </CopyToClipboard>
            </div>
        );
    }

    return null;
};

type DomainSubtitleProps = {
    domain: string;
    ips: string[];
};

const DomainSubtitle = ({ domain, ips }: DomainSubtitleProps) => {
    const first = ips[0];
    const extra = ips.length - 1;

    return (
        <>
            <div>
                <CopyToClipboard message={domain}>
                    <span className={"text-xs font-mono text-nb-gray-400 truncate"}>
                        {domain}
                    </span>
                </CopyToClipboard>
            </div>
            {first && (
                <div className={"flex items-center gap-1.5 min-w-0"}>
                    <CopyToClipboard message={first}>
                        <span className={"text-xs font-mono text-nb-gray-500 truncate"}>
                            {first}
                        </span>
                    </CopyToClipboard>
                    {extra > 0 && <ResolvedIpsPopover ips={ips} />}
                </div>
            )}
        </>
    );
};

const ResolvedIpsPopover = ({ ips }: { ips: string[] }) => {
    const { t } = useTranslation();
    const extra = ips.length - 1;

    return (
        <Popover.Root>
            <Popover.Trigger asChild>
                <button
                    type={"button"}
                    onClick={(e) => e.stopPropagation()}
                    className={cn(
                        "shrink-0 rounded bg-nb-gray-900 hover:bg-nb-gray-850",
                        "px-1.5 py-0.5 text-[10px] font-medium text-nb-gray-300",
                        "wails-no-draggable cursor-pointer outline-none",
                    )}
                >
                    {t("networks.ips.more", { count: extra })}
                </button>
            </Popover.Trigger>
            <Popover.Portal>
                <Popover.Content
                    side={"bottom"}
                    align={"start"}
                    sideOffset={6}
                    className={cn(
                        "z-50 w-64 max-h-72 overflow-auto",
                        "rounded-lg border border-nb-gray-900 bg-nb-gray-935",
                        "p-2 shadow-lg outline-none",
                    )}
                >
                    <div
                        className={
                            "px-1 pb-1 text-[10px] uppercase tracking-wide text-nb-gray-500"
                        }
                    >
                        {t("networks.ips.heading")}
                    </div>
                    <ul className={"flex flex-col"}>
                        {ips.map((ip) => (
                            <li key={ip}>
                                <CopyToClipboard
                                    message={ip}
                                    className={"px-1 py-0.5"}
                                >
                                    <span
                                        className={
                                            "font-mono text-[0.72rem] text-nb-gray-200 break-all"
                                        }
                                    >
                                        {ip}
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

type ToggleProps = {
    checked: boolean;
    onChange: () => void;
    label: string;
    mixed?: boolean;
};

export const NetworkToggle = ({ checked, onChange, label, mixed }: ToggleProps) => (
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
                mixed
                    ? "translate-x-2.5"
                    : checked
                      ? "translate-x-[1.125rem]"
                      : "translate-x-0.5",
            )}
        />
    </button>
);
