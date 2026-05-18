import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsNetwork() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();

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
                <FancyToggleSwitch
                    value={!config.disableClientRoutes}
                    onChange={(v) => setField("disableClientRoutes", !v)}
                    label={t("settings.network.clientRoutes.label")}
                    helpText={t("settings.network.clientRoutes.help")}
                />
                <FancyToggleSwitch
                    value={!config.disableServerRoutes}
                    onChange={(v) => setField("disableServerRoutes", !v)}
                    label={t("settings.network.serverRoutes.label")}
                    helpText={t("settings.network.serverRoutes.help")}
                />
                <FancyToggleSwitch
                    value={!config.disableIpv6}
                    onChange={(v) => setField("disableIpv6", !v)}
                    label={"Enable IPv6"}
                    helpText={"Use IPv6 addressing for the NetBird overlay network."}
                />
            </SectionGroup>
        </>
    );
}
