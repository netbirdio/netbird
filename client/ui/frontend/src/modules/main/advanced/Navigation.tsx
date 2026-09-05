import { type ComponentType, type KeyboardEvent, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Layers3Icon, type LucideProps, MonitorSmartphoneIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { useNavSection, type NavSection } from "@/contexts/NavSectionContext";
import { useStatus } from "@/contexts/StatusContext";
import { useRestrictions } from "@/contexts/RestrictionsContext";

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

    const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

    const focusTab = (value: NavSection) => {
        setSection(value);
        requestAnimationFrame(() => tabRefs.current[value]?.focus());
    };

    const handleKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
        const enabled = tabs.filter((t) => isConnected || t.value === section);
        if (enabled.length < 2) return;
        const currentIndex = enabled.findIndex((t) => t.value === section);
        if (currentIndex === -1) return;
        let nextIndex: number;
        switch (e.key) {
            case "ArrowRight":
                nextIndex = (currentIndex + 1) % enabled.length;
                break;
            case "ArrowLeft":
                nextIndex = (currentIndex - 1 + enabled.length) % enabled.length;
                break;
            case "Home":
                nextIndex = 0;
                break;
            case "End":
                nextIndex = enabled.length - 1;
                break;
            default:
                return;
        }
        e.preventDefault();
        focusTab(enabled[nextIndex].value);
    };

    return (
        <div
            role={"tablist"}
            aria-orientation={"horizontal"}
            aria-label={t("nav.peers.title")}
            className={"wails-no-draggable flex shrink-0 items-stretch"}
        >
            {tabs.map((tab, index) => {
                const isActive = tab.value === section;
                const isDisabled = !isConnected && !isActive;
                const isFirst = index === 0;
                const isLast = index === tabs.length - 1;
                const Icon = tab.icon;
                return (
                    <button
                        key={tab.value}
                        ref={(el) => {
                            tabRefs.current[tab.value] = el;
                        }}
                        type={"button"}
                        role={"tab"}
                        aria-selected={isActive}
                        aria-controls={`nb-tabpanel-${tab.value}`}
                        id={`nb-tab-${tab.value}`}
                        tabIndex={isActive ? 0 : -1}
                        onClick={() => setSection(tab.value)}
                        onKeyDown={handleKeyDown}
                        disabled={isDisabled}
                        className={cn(
                            "group relative flex flex-1 items-center justify-center",
                            "gap-2.5 px-5 py-3.5",
                            "outline-none transition-all",
                            isFirst && "rounded-tl-xl",
                            isLast && "rounded-tr-xl",
                            "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
                            isActive ? "text-netbird" : "text-nb-gray-400 hover:text-nb-gray-300",
                            isDisabled ? "cursor-not-allowed opacity-50" : "cursor-default",
                        )}
                    >
                        <Icon size={14} aria-hidden={"true"} />
                        <span className={"text-sm font-normal"}>{tab.label}</span>
                        <span
                            aria-hidden={"true"}
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
