import { useTranslation } from "react-i18next";
import { CardNavItem } from "@/components/CardNavItem.tsx";
import { Layers3Icon, MonitorSmartphoneIcon } from "lucide-react";
import deFlag from "@/assets/flags/1x1/de.svg";

type Props = {
    peersActive?: boolean;
    onPeersClick?: () => void;
};

export const Navigation = ({ peersActive = false, onPeersClick }: Props) => {
    const { t } = useTranslation();
    return (
        <nav className={"w-full flex flex-col gap-1 mt-auto"}>
            <CardNavItem
                icon={MonitorSmartphoneIcon}
                title={t("nav.peers.title")}
                description={t("nav.peers.description", { online: 17, total: 25 })}
                active={peersActive}
                onClick={onPeersClick}
            />
            <CardNavItem
                icon={Layers3Icon}
                title={t("nav.resources.title")}
                description={t("nav.resources.description", { active: 13, total: 16 })}
                iconSize={14}
            />
            <CardNavItem
                iconNode={
                    <img
                        src={deFlag}
                        alt={t("nav.exitNode.flagAlt", { country: "Germany" })}
                        className={
                            "h-6 w-6 rounded-full border-[3px] border-nb-gray-850 shrink-0"
                        }
                    />
                }
                title={t("nav.exitNode.title", { location: "Berlin" })}
                description={"100.92.14.37"}
            />
        </nav>
    );
};
