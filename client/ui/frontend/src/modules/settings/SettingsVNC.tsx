import { useTranslation } from "react-i18next";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useGuardedControl } from "@/modules/settings/PrivilegeGuard.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

export function SettingsVNC() {
    const { t } = useTranslation();
    const { config } = useSettings();
    const { mdm } = useRestrictions();
    const guarded = useGuardedControl();
    const isVNCServerEnabled = config.serverVncAllowed;
    const vncServerManaged = mdm.allowServerVNC != null;

    const vncServer = guarded("serverVncAllowed", (p) => p.allowVncServer);
    // Inverted control: the guarded direction is switching the approval prompt
    // off, so the already-disabled state is the one-way one.
    const vncApproval = guarded("disableVncApproval", (p) => p.disableVncApproval, true);

    return (
        <>
            <SectionGroup title={t("settings.vnc.section.server")}>
                <FancyToggleSwitch
                    value={config.serverVncAllowed}
                    onChange={vncServer.apply}
                    label={t("settings.vnc.server.label")}
                    helpText={t("settings.vnc.server.help")}
                    disabled={vncServerManaged || vncServer.disabled}
                />
                {!vncServerManaged && vncServer.hint}
            </SectionGroup>

            {!mdm.disableVNCApproval && (
                <SectionGroup
                    title={t("settings.vnc.section.approval")}
                    disabled={!isVNCServerEnabled}
                >
                    <FancyToggleSwitch
                        value={!config.disableVncApproval}
                        onChange={(v) => vncApproval.apply(!v)}
                        label={t("settings.vnc.approval.label")}
                        helpText={t("settings.vnc.approval.help")}
                        disabled={vncApproval.disabled}
                    />
                    {vncApproval.hint}
                </SectionGroup>
            )}
        </>
    );
}
