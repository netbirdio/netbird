import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";
import type { Restrictions } from "@bindings/services/models.js";

// routingDnsHasControls reports whether the routing and DNS section has a
// control left once the MDM-managed ones are hidden.
function routingDnsHasControls(mdm: Restrictions["mdm"]): boolean {
    return !(
        mdm.disableDNS &&
        mdm.disableClientRoutes &&
        mdm.disableServerRoutes &&
        mdm.disableIPv6
    );
}

// networkTabHasControls reports whether the Network tab has anything left to
// show once the MDM-managed controls are hidden.
export function networkTabHasControls(mdm: Restrictions["mdm"]): boolean {
    return !mdm.networkMonitor || routingDnsHasControls(mdm);
}

export function SettingsNetwork() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mdm } = useRestrictions();
    const showRoutingDnsSection = routingDnsHasControls(mdm);

    return (
        <>
            {!mdm.networkMonitor && (
                <SectionGroup title={t("settings.network.section.connectivity")}>
                    <FancyToggleSwitch
                        value={config.networkMonitor}
                        onChange={(v) => setField("networkMonitor", v)}
                        label={t("settings.network.monitor.label")}
                        helpText={t("settings.network.monitor.help")}
                    />
                </SectionGroup>
            )}

            {showRoutingDnsSection && (
                <SectionGroup title={t("settings.network.section.routingDns")}>
                    {!mdm.disableDNS && (
                        <FancyToggleSwitch
                            value={!config.disableDns}
                            onChange={(v) => setField("disableDns", !v)}
                            label={t("settings.network.dns.label")}
                            helpText={t("settings.network.dns.help")}
                        />
                    )}
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
                    {!mdm.disableIPv6 && (
                        <FancyToggleSwitch
                            value={!config.disableIpv6}
                            onChange={(v) => setField("disableIpv6", !v)}
                            label={t("settings.network.ipv6.label")}
                            helpText={t("settings.network.ipv6.help")}
                        />
                    )}
                </SectionGroup>
            )}
        </>
    );
}
