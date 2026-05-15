import { useTranslation } from "react-i18next";
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
} from "lucide-react";

export const SettingsNavigationTriggers = () => {
    const { t } = useTranslation();
    const { updateAvailable } = useClientVersion();

    const aboutAdornment = updateAvailable ? (
        <Tooltip content={t("settings.tabs.updateAvailable")} side={"right"}>
            <UpdateBadge />
        </Tooltip>
    ) : undefined;

    return (
        <div className={"flex flex-col w-52 shrink-0 items-center select-none"}>
        <VerticalTabs.List>
            <VerticalTabs.Trigger
                value={"general"}
                icon={SlidersHorizontalIcon}
                title={t("settings.tabs.general")}
            />
            <VerticalTabs.Trigger
                value={"network"}
                icon={NetworkIcon}
                title={t("settings.tabs.network")}
            />
            <VerticalTabs.Trigger
                value={"security"}
                icon={ShieldIcon}
                title={t("settings.tabs.security")}
            />
            <VerticalTabs.Trigger
                value={"ssh"}
                icon={SquareTerminalIcon}
                title={t("settings.tabs.ssh")}
            />
            <VerticalTabs.Trigger
                value={"advanced"}
                icon={BoltIcon}
                title={t("settings.tabs.advanced")}
            />
            <VerticalTabs.Trigger
                value={"troubleshooting"}
                icon={LifeBuoyIcon}
                title={t("settings.tabs.troubleshooting")}
            />
            <VerticalTabs.Trigger
                value={"about"}
                icon={InfoIcon}
                title={t("settings.tabs.about")}
                adornment={aboutAdornment}
            />
        </VerticalTabs.List>
        </div>
    );
};
