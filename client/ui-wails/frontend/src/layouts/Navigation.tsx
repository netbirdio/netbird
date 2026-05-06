import { NavItem } from "@/components/NavItem.tsx";
import {
    Layers3Icon,
    MonitorSmartphoneIcon,
    SquareArrowUpRight,
} from "lucide-react";

export const Navigation = () => {
    return (
        <nav className={"w-full flex flex-col gap-1 mt-8"}>
            <NavItem
                icon={MonitorSmartphoneIcon}
                title={"Peers"}
                description={"13 of 16 Online"}
                active
            />
            <NavItem
                icon={Layers3Icon}
                title={"Resources"}
                description={"13 of 16 Active"}
                iconSize={14}
            />
            <NavItem
                icon={SquareArrowUpRight}
                title={"Exit Node Berlin"}
                description={"192.168..."}
                iconSize={14}
            />
        </nav>
    );
};
