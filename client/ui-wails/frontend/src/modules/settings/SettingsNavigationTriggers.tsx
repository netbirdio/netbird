import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import {
    BoltIcon,
    InfoIcon,
    LifeBuoyIcon,
    NetworkIcon,
    ShieldIcon,
    SlidersHorizontalIcon,
    SquareTerminalIcon,
} from "lucide-react";

export const SettingsNavigationTriggers = () => {
    return (
        <div className={"flex flex-col w-52 shrink-0 items-center"}>
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
            />
        </VerticalTabs.List>
        </div>
    );
};
