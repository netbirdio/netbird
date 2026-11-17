import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";
import type { Restrictions } from "@bindings/services/models.js";

function firewallHasControls(mdm: Restrictions["mdm"]): boolean {
    return !(mdm.blockInbound && mdm.blockLANAccess);
}

function encryptionHasControls(mdm: Restrictions["mdm"]): boolean {
    return !(mdm.rosenpassEnabled && mdm.rosenpassPermissive);
}

// securityTabHasControls reports whether the Security tab has anything left to
// show once the MDM-managed controls are hidden.
export function securityTabHasControls(mdm: Restrictions["mdm"]): boolean {
    return firewallHasControls(mdm) || encryptionHasControls(mdm);
}

export function SettingsSecurity() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mdm } = useRestrictions();
    const hideRosenpassEnabled = mdm.rosenpassEnabled;
    // Shown, disabled, while Rosenpass is off: the tab must not depend on the
    // profile value to know whether it has a control left.
    const hideRosenpassPermissive = mdm.rosenpassPermissive;
    const showFirewallSection = firewallHasControls(mdm);
    const showEncryptionSection = encryptionHasControls(mdm);

    return (
        <>
            {showFirewallSection && (
                <SectionGroup title={t("settings.security.section.firewall")}>
                    {!mdm.blockInbound && (
                        <FancyToggleSwitch
                            value={config.blockInbound}
                            onChange={(v) => setField("blockInbound", v)}
                            label={t("settings.security.blockInbound.label")}
                            helpText={t("settings.security.blockInbound.help")}
                        />
                    )}
                    {!mdm.blockLANAccess && (
                        <FancyToggleSwitch
                            value={config.blockLanAccess}
                            onChange={(v) => setField("blockLanAccess", v)}
                            label={t("settings.security.blockLan.label")}
                            helpText={t("settings.security.blockLan.help")}
                        />
                    )}
                </SectionGroup>
            )}

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
                            helpText={
                                <>
                                    {t("settings.security.rosenpass.help")}
                                    <span className={"mt-1 block"}>
                                        {t("settings.security.rosenpass.deprecated")}
                                    </span>
                                </>
                            }
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
