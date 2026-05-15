import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

export function SettingsSecurity() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    return (
        <>
            <SectionGroup title={t("settings.security.section.firewall")}>
                <FancyToggleSwitch
                    value={config.blockInbound}
                    onChange={(v) => setField("blockInbound", v)}
                    label={t("settings.security.blockInbound.label")}
                    helpText={t("settings.security.blockInbound.help")}
                />
                <FancyToggleSwitch
                    value={config.blockLanAccess}
                    onChange={(v) => setField("blockLanAccess", v)}
                    label={t("settings.security.blockLan.label")}
                    helpText={t("settings.security.blockLan.help")}
                />
            </SectionGroup>

            <SectionGroup title={t("settings.security.section.encryption")}>
                <FancyToggleSwitch
                    value={config.rosenpassEnabled}
                    onChange={(v) => {
                        setField("rosenpassEnabled", v);
                        if (!v) setField("rosenpassPermissive", false);
                    }}
                    label={t("settings.security.rosenpass.label")}
                    helpText={t("settings.security.rosenpass.help")}
                />
                <FancyToggleSwitch
                    value={config.rosenpassPermissive}
                    onChange={(v) => setField("rosenpassPermissive", v)}
                    label={t("settings.security.rosenpassPermissive.label")}
                    helpText={t("settings.security.rosenpassPermissive.help")}
                    disabled={!config.rosenpassEnabled}
                />
            </SectionGroup>
        </>
    );
}
