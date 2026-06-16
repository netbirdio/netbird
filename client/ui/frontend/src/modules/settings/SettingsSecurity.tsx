import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

export function SettingsSecurity() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mdm } = useRestrictions();
    const hideRosenpassEnabled = mdm.rosenpassEnabled;
    const hideRosenpassPermissive =
        mdm.rosenpassPermissive || (mdm.rosenpassEnabled && !config.rosenpassEnabled);
    const showEncryptionSection = !(hideRosenpassEnabled && hideRosenpassPermissive);

    return (
        <>
            <SectionGroup title={t("settings.security.section.firewall")}>
                {!mdm.blockInbound && (
                    <FancyToggleSwitch
                        value={config.blockInbound}
                        onChange={(v) => setField("blockInbound", v)}
                        label={t("settings.security.blockInbound.label")}
                        helpText={t("settings.security.blockInbound.help")}
                    />
                )}
                <FancyToggleSwitch
                    value={config.blockLanAccess}
                    onChange={(v) => setField("blockLanAccess", v)}
                    label={t("settings.security.blockLan.label")}
                    helpText={t("settings.security.blockLan.help")}
                />
            </SectionGroup>

            {showEncryptionSection && (
                <SectionGroup title={t("settings.security.section.encryption")}>
                    {!hideRosenpassEnabled && (
                        <FancyToggleSwitch
                            value={config.rosenpassEnabled}
                            onChange={(v) => {
                                setField("rosenpassEnabled", v);
                                if (!v) setField("rosenpassPermissive", false);
                            }}
                            label={t("settings.security.rosenpass.label")}
                            helpText={t("settings.security.rosenpass.help")}
                        />
                    )}
                    {!hideRosenpassPermissive && (
                        <FancyToggleSwitch
                            value={config.rosenpassPermissive}
                            onChange={(v) => setField("rosenpassPermissive", v)}
                            label={t("settings.security.rosenpassPermissive.label")}
                            helpText={t("settings.security.rosenpassPermissive.help")}
                            disabled={!config.rosenpassEnabled}
                        />
                    )}
                </SectionGroup>
            )}
        </>
    );
}
