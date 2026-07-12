import { useTranslation } from "react-i18next";
import { Tooltip } from "@/components/Tooltip.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { UpdateBadge } from "@/modules/auto-update/UpdateBadge.tsx";
import { useClientVersion } from "@/contexts/ClientVersionContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";
import {
    BoltIcon,
    InfoIcon,
    LifeBuoyIcon,
    MonitorIcon,
    NetworkIcon,
    ShieldIcon,
    SlidersHorizontalIcon,
    SquareTerminalIcon,
    UserCircleIcon,
} from "lucide-react";

export const SettingsNavigation = () => {
    const { t } = useTranslation();
    const { updateAvailable } = useClientVersion();
    const { mdm, features } = useRestrictions();
    const showSsh = mdm.allowServerSSH ?? !features.disableUpdateSettings;

    const aboutAdornment = updateAvailable ? (
        <Tooltip content={t("settings.tabs.updateAvailable")} side={"right"}>
            <UpdateBadge />
        </Tooltip>
    ) : undefined;

    return (
        <div className={"flex w-52 shrink-0 select-none flex-col items-center"}>
            <VerticalTabs.List aria-label={t("settings.nav.label")}>
                <VerticalTabs.Trigger
                    value={"general"}
                    icon={SlidersHorizontalIcon}
                    title={t("settings.tabs.general")}
                />
                {!features.disableUpdateSettings && (
                    <>
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
                    </>
                )}
                {!features.disableProfiles && (
                    <VerticalTabs.Trigger
                        value={"profiles"}
                        icon={UserCircleIcon}
                        title={t("settings.tabs.profiles")}
                    />
                )}
                {showSsh && (
                    <VerticalTabs.Trigger
                        value={"ssh"}
                        icon={SquareTerminalIcon}
                        title={t("settings.tabs.ssh")}
                    />
                )}
                {!features.disableUpdateSettings && (
                    <VerticalTabs.Trigger
                        value={"vnc"}
                        icon={MonitorIcon}
                        title={t("settings.tabs.vnc")}
                    />
                )}
                {!features.disableUpdateSettings && (
                    <VerticalTabs.Trigger
                        value={"advanced"}
                        icon={BoltIcon}
                        title={t("settings.tabs.advanced")}
                    />
                )}
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
