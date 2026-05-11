import { Tooltip } from "@/components/Tooltip.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { useStatus } from "@/hooks/useStatus";
import {
    ArrowUpCircleIcon,
    BoltIcon,
    InfoIcon,
    LifeBuoyIcon,
    NetworkIcon,
    ShieldIcon,
    SlidersHorizontalIcon,
    SquareTerminalIcon,
} from "lucide-react";

export const SettingsNavigationTriggers = () => {
    const { status } = useStatus();
    const updateAvailable = (status?.events ?? []).some((e) =>
        Boolean(e.metadata?.["new_version_available"]),
    );

    const aboutAdornment = updateAvailable ? (
        <Tooltip content={"Update Available"} side={"right"}>
            <div className={"relative flex items-center justify-center"}>
                <span
                    className={
                        "animate-ping absolute inline-flex h-[15px] w-[15px] rounded-full bg-netbird opacity-20 pointer-events-none"
                    }
                />
                <ArrowUpCircleIcon size={15} className={"text-netbird"} />
            </div>
        </Tooltip>
    ) : undefined;

    return (
        <div className={"flex flex-col w-52 shrink-0 items-center select-none"}>
        <VerticalTabs.List>
            <VerticalTabs.Trigger
                value={"general"}
                icon={SlidersHorizontalIcon}
                title={"General"}
            />
            <VerticalTabs.Trigger
                value={"network"}
                icon={NetworkIcon}
                title={"Network"}
            />
            <VerticalTabs.Trigger
                value={"security"}
                icon={ShieldIcon}
                title={"Security"}
            />
            <VerticalTabs.Trigger
                value={"ssh"}
                icon={SquareTerminalIcon}
                title={"SSH"}
            />
            <VerticalTabs.Trigger
                value={"advanced"}
                icon={BoltIcon}
                title={"Advanced"}
            />
            <VerticalTabs.Trigger
                value={"troubleshooting"}
                icon={LifeBuoyIcon}
                title={"Troubleshooting"}
            />
            <VerticalTabs.Trigger
                value={"about"}
                icon={InfoIcon}
                title={"About"}
                adornment={aboutAdornment}
            />
        </VerticalTabs.List>
        </div>
    );
};
