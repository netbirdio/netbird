import { ComponentType } from "react";
import { useTranslation } from "react-i18next";
import { Layers3Icon, LucideProps, MonitorSmartphoneIcon, SquareArrowUpRight } from "lucide-react";
import { cn } from "@/lib/cn";
import { useNavSection, type NavSection } from "@/contexts/NavSectionContext";
import { useStatus } from "@/contexts/StatusContext";

type TabEntry = {
    value: NavSection;
    label: string;
    icon: ComponentType<LucideProps>;
};

export const Navigation = () => {
    const { t } = useTranslation();
    const { section, setSection } = useNavSection();
    const { status } = useStatus();
    const isConnected = status?.status === "Connected";

    const tabs: TabEntry[] = [
        {
            value: "peers",
            label: t("nav.peers.title"),
            icon: MonitorSmartphoneIcon,
        },
        {
            value: "networks",
            label: t("nav.resources.title"),
            icon: Layers3Icon,
        },
        {
            value: "exitNode",
            label: t("nav.exitNode.title"),
            icon: ExitNodeIcon,
        },
    ];

    return (
        <div className={"wails-no-draggable shrink-0 flex items-stretch "}>
            {tabs.map((tab) => {
                const isActive = tab.value === section;
                const isDisabled = !isConnected && !isActive;
                const Icon = tab.icon;
                return (
                    <button
                        key={tab.value}
                        type={"button"}
                        onClick={() => setSection(tab.value)}
                        disabled={isDisabled}
                        className={cn(
                            "group relative flex flex-1 items-center justify-center",
                            "gap-2.5 px-5 py-3.5",
                            "outline-none transition-all",
                            isActive ? "text-netbird" : "text-nb-gray-400 hover:text-nb-gray-300",
                            isDisabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
                        )}
                    >
                        <Icon size={14} />
                        <span className={"text-sm font-normal"}>{tab.label}</span>
                        <span
                            className={cn(
                                "absolute inset-x-0 bottom-0 h-px transition-all",
                                isActive
                                    ? "bg-netbird"
                                    : "bg-nb-gray-910 group-hover:bg-nb-gray-700",
                            )}
                        />
                    </button>
                );
            })}
        </div>
    );
};

const ExitNodeIcon = ({ size, ...props }: LucideProps) => (
    <SquareArrowUpRight
        {...props}
        size={typeof size === "number" ? size - 2 : size}
        className={cn("rotate-45", props.className)}
    />
);

export type { NavSection } from "@/contexts/NavSectionContext";
