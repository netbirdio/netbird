import { Tooltip } from "@/components/Tooltip.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { UpdateBadge } from "@/modules/auto-update/UpdateBadge.tsx";
import { useClientVersion } from "@/modules/auto-update/ClientVersionContext.tsx";
import {
    BoltIcon,
    InfoIcon,
    LifeBuoyIcon,
    NetworkIcon,
    ShieldIcon,
    SlidersHorizontalIcon,
    SquareTerminalIcon,
    SwatchBookIcon,
} from "lucide-react";

export const SettingsNavigationTriggers = () => {
    const { updateAvailable } = useClientVersion();

    const aboutAdornment = updateAvailable ? (
        <Tooltip content={"Update Available"} side={"right"}>
            <UpdateBadge />
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
                value={"appearance"}
                icon={SwatchBookIcon}
                title={"Appearance"}
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
