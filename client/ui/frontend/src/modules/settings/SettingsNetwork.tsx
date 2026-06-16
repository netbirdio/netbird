import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

export function SettingsNetwork() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mdm } = useRestrictions();

    return (
        <>
            <SectionGroup title={t("settings.network.section.connectivity")}>
                <FancyToggleSwitch
                    value={config.lazyConnectionEnabled}
                    onChange={(v) => setField("lazyConnectionEnabled", v)}
                    label={t("settings.network.lazy.label")}
                    helpText={t("settings.network.lazy.help")}
                />
                <FancyToggleSwitch
                    value={config.networkMonitor}
                    onChange={(v) => setField("networkMonitor", v)}
                    label={t("settings.network.monitor.label")}
                    helpText={t("settings.network.monitor.help")}
                />
            </SectionGroup>

            <SectionGroup title={t("settings.network.section.routingDns")}>
                <FancyToggleSwitch
                    value={!config.disableDns}
                    onChange={(v) => setField("disableDns", !v)}
                    label={t("settings.network.dns.label")}
                    helpText={t("settings.network.dns.help")}
                />
                {!mdm.disableClientRoutes && (
                    <FancyToggleSwitch
                        value={!config.disableClientRoutes}
                        onChange={(v) => setField("disableClientRoutes", !v)}
                        label={t("settings.network.clientRoutes.label")}
                        helpText={t("settings.network.clientRoutes.help")}
                    />
                )}
                {!mdm.disableServerRoutes && (
                    <FancyToggleSwitch
                        value={!config.disableServerRoutes}
                        onChange={(v) => setField("disableServerRoutes", !v)}
                        label={t("settings.network.serverRoutes.label")}
                        helpText={t("settings.network.serverRoutes.help")}
                    />
                )}
                <FancyToggleSwitch
                    value={!config.disableIpv6}
                    onChange={(v) => setField("disableIpv6", !v)}
                    label={t("settings.network.ipv6.label")}
                    helpText={t("settings.network.ipv6.help")}
                />
            </SectionGroup>
        </>
    );
}
