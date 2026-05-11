import { CardNavItem } from "@/components/CardNavItem.tsx";
import {
    Layers3Icon,
    MonitorSmartphoneIcon,
    SquareArrowUpRight,
} from "lucide-react";

type Props = {
    peersActive?: boolean;
    onPeersClick?: () => void;
};

export const Navigation = ({ peersActive = false, onPeersClick }: Props) => {
    return (
        <nav className={"w-full flex flex-col gap-1 mt-auto"}>
            <CardNavItem
                icon={MonitorSmartphoneIcon}
                title={"Peers"}
                description={"13 of 16 Online"}
                active={peersActive}
                onClick={onPeersClick}
            />
            <CardNavItem
                icon={Layers3Icon}
                title={"Resources"}
                description={"13 of 16 Active"}
                iconSize={14}
            />
            <CardNavItem
                icon={SquareArrowUpRight}
                title={"Exit Node Berlin"}
                description={"192.168..."}
                iconSize={14}
            />
        </nav>
    );
};
