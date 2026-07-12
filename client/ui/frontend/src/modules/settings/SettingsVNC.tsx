import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";

export function SettingsVNC() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const isVNCServerEnabled = config.serverVncAllowed;

    return (
        <>
            <SectionGroup title={t("settings.vnc.section.server")}>
                <FancyToggleSwitch
                    value={config.serverVncAllowed}
                    onChange={(v) => setField("serverVncAllowed", v)}
                    label={t("settings.vnc.server.label")}
                    helpText={t("settings.vnc.server.help")}
                />
            </SectionGroup>

            <SectionGroup title={t("settings.vnc.section.approval")} disabled={!isVNCServerEnabled}>
                <FancyToggleSwitch
                    value={!config.disableVncApproval}
                    onChange={(v) => setField("disableVncApproval", !v)}
                    label={t("settings.vnc.approval.label")}
                    helpText={t("settings.vnc.approval.help")}
                />
            </SectionGroup>
        </>
    );
}
