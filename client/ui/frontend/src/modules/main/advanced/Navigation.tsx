import { ComponentType } from "react";
import { useTranslation } from "react-i18next";
import { Layers3Icon, LucideProps, MonitorSmartphoneIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { useNavSection, type NavSection } from "@/contexts/NavSectionContext";
import { useStatus } from "@/contexts/StatusContext";
import { useRestrictions } from "@/contexts/RestrictionsContext";
import { useEffect } from "react";

type TabEntry = {
    value: NavSection;
    label: string;
    icon: ComponentType<LucideProps>;
};

export const Navigation = () => {
    const { t } = useTranslation();
    const { section, setSection } = useNavSection();
    const { status } = useStatus();
    const { features } = useRestrictions();
    const isConnected = status?.status === "Connected";

    // Reset back to peers tab if mdm or feature flag flipped it
    useEffect(() => {
        if (features.disableNetworks && section === "networks") {
            setSection("peers");
        }
    }, [features.disableNetworks, section, setSection]);

    const tabs: TabEntry[] = [
        {
            value: "peers",
            label: t("nav.peers.title"),
            icon: MonitorSmartphoneIcon,
        },
    ];
    if (!features.disableNetworks) {
        tabs.push({
            value: "networks",
            label: t("nav.resources.title"),
            icon: Layers3Icon,
        });
    }

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
                            isDisabled ? "opacity-50 cursor-not-allowed" : "cursor-default",
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

export type { NavSection } from "@/contexts/NavSectionContext";
