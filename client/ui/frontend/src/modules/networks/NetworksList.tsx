import * as Popover from "@radix-ui/react-popover";
import { GlobeIcon, NetworkIcon, WorkflowIcon } from "lucide-react";
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

const ResourceIcon = ({ type }: { type: ResourceType }) => {
    if (type === "host") return <WorkflowIcon size={15} />;
    if (type === "domain") return <GlobeIcon size={15} />;
    return <NetworkIcon size={15} />;
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
                    className={"flex items-center gap-3 px-7 py-3 min-w-0"}
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
                    <span className={"shrink-0 text-nb-gray-400"}>
                        <ResourceIcon type={resourceTypeOf(n)} />
                    </span>
                    <div className={"min-w-0 flex-1 flex flex-col gap-0.5"}>
                        <CopyToClipboard message={n.id}>
                            <span
                                className={
                                    "text-[0.81rem] font-medium text-nb-gray-100"
                                }
                            >
                                {n.id}
                            </span>
                        </CopyToClipboard>
                        <Subtitle network={n} />
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
            <CopyToClipboard message={network.range}>
                <span
                    className={
                        "text-xs font-mono text-nb-gray-400 truncate"
                    }
                >
                    {network.range}
                </span>
            </CopyToClipboard>
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
        <div className={"flex items-center gap-1.5 text-xs min-w-0"}>
            <CopyToClipboard message={domain}>
                <span className={"font-mono text-nb-gray-400 truncate"}>
                    {domain}
                </span>
            </CopyToClipboard>
            {first && (
                <>
                    <span className={"text-nb-gray-600"}>·</span>
                    <CopyToClipboard message={first}>
                        <span
                            className={"font-mono text-nb-gray-500 truncate"}
                        >
                            {first}
                        </span>
                    </CopyToClipboard>
                    {extra > 0 && <ResolvedIpsPopover ips={ips} />}
                </>
            )}
        </div>
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
};

const NetworkToggle = ({ checked, onChange, label }: ToggleProps) => (
    <button
        type={"button"}
        role={"switch"}
        aria-checked={checked}
        aria-label={label}
        onClick={onChange}
        className={cn(
            "shrink-0 inline-flex h-4 w-7 items-center rounded-full",
            "transition-colors cursor-pointer wails-no-draggable",
            checked ? "bg-netbird" : "bg-nb-gray-700",
        )}
    >
        <span
            className={cn(
                "inline-block h-3 w-3 rounded-full bg-white transition-transform",
                checked ? "translate-x-3.5" : "translate-x-0.5",
            )}
        />
    </button>
);
