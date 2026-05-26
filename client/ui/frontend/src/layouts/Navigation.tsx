import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Layers3Icon, MonitorSmartphoneIcon, SquareArrowUpRight } from "lucide-react";
import { CardNavItem } from "@/components/CardNavItem.tsx";
import { cn } from "@/lib/cn";
import { useStatus } from "@/modules/daemon-status/StatusContext";
import { useNetworks } from "@/modules/networks/NetworksContext";

export type NavSection = "peers" | "networks" | "exitNode";

type Props = {
    active: NavSection;
    onSelect: (section: NavSection) => void;
};

export const Navigation = ({ active, onSelect }: Props) => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const { networkRoutes, exitNodes, activeExitNode } = useNetworks();

    const peerCounts = useMemo(() => {
        const peers = status?.peers ?? [];
        const online = peers.filter((p) => p.connStatus === "Connected").length;
        return { online, total: peers.length };
    }, [status?.peers]);

    const networkCounts = useMemo(
        () => ({
            active: networkRoutes.filter((r) => r.selected).length,
            total: networkRoutes.length,
        }),
        [networkRoutes],
    );

    const exitNodeDescription = activeExitNode
        ? activeExitNode.id
        : t("nav.exitNode.none", { total: exitNodes.length });

    return (
        <nav className={"w-full flex flex-col gap-1 mt-auto"}>
            <CardNavItem
                icon={MonitorSmartphoneIcon}
                title={t("nav.peers.title")}
                description={t("nav.peers.description", peerCounts)}
                active={active === "peers"}
                onClick={() => onSelect("peers")}
            />
            <CardNavItem
                icon={Layers3Icon}
                title={t("nav.resources.title")}
                description={t("nav.resources.description", networkCounts)}
                iconSize={14}
                active={active === "networks"}
                onClick={() => onSelect("networks")}
            />
            <CardNavItem
                iconNode={
                    <SquareArrowUpRight
                        size={14}
                        className={cn(
                            "transition-colors duration-150 rotate-45",
                            active === "exitNode"
                                ? "text-nb-gray-200"
                                : "text-nb-gray-400",
                        )}
                    />
                }
                title={t("nav.exitNode.title")}
                description={exitNodeDescription}
                active={active === "exitNode"}
                onClick={() => onSelect("exitNode")}
            />
        </nav>
    );
};
