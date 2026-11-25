import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { Select } from "@/components/inputs/Select";
import HelpText from "@/components/typography/HelpText.tsx";
import { Label } from "@/components/typography/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

const DNS_PRIMARY_MODES = ["auto", "never", "always"] as const;

export function SettingsNetwork() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mdm } = useRestrictions();

    return (
        <>
            <SectionGroup title={t("settings.network.section.connectivity")}>
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
                <div className={"flex items-center justify-between gap-4"}>
                    <div className={"min-w-0"}>
                        <Label>{t("settings.network.dnsPrimaryMode.label")}</Label>
                        <HelpText margin={false}>
                            {t("settings.network.dnsPrimaryMode.help")}
                        </HelpText>
                    </div>
                    <div className={"shrink-0"}>
                        <Select
                            value={config.dnsPrimaryMode || "auto"}
                            options={DNS_PRIMARY_MODES.map((value) => ({
                                value,
                                label: t(`settings.network.dnsPrimaryMode.${value}`),
                            }))}
                            onChange={(v) => setField("dnsPrimaryMode", v)}
                            ariaLabel={t("settings.network.dnsPrimaryMode.label")}
                        />
                    </div>
                </div>
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
