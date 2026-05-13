import { CardNavItem } from "@/components/CardNavItem.tsx";
import { Layers3Icon, MonitorSmartphoneIcon } from "lucide-react";
import deFlag from "@/assets/flags/1x1/de.svg";
import { useAppearance } from "@/modules/appearance/AppearanceContext.tsx";

type Props = {
    peersActive?: boolean;
    onPeersClick?: () => void;
};

export const Navigation = ({ peersActive = false, onPeersClick }: Props) => {
    const { showPeersNav, showResourcesNav, showExitNodeNav } = useAppearance();

    return (
        <nav className={"w-full flex flex-col gap-1 mt-auto"}>
            {showPeersNav && (
                <CardNavItem
                    icon={MonitorSmartphoneIcon}
                    title={"Peers"}
                    description={"17 of 25 Online"}
                    active={peersActive}
                    onClick={onPeersClick}
                />
            )}
            {showResourcesNav && (
                <CardNavItem
                    icon={Layers3Icon}
                    title={"Resources"}
                    description={"13 of 16 Active"}
                    iconSize={14}
                />
            )}
            {showExitNodeNav && (
                <CardNavItem
                    iconNode={
                        <img
                            src={deFlag}
                            alt={"Germany"}
                            className={
                                "h-6 w-6 rounded-full border-[3px] border-nb-gray-850 shrink-0"
                            }
                        />
                    }
                    title={"Exit Node Berlin"}
                    description={"100.92.14.37"}
                />
            )}
        </nav>
    );
};
