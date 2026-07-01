import { useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/buttons/Button";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useAutostartSetting, useSettings } from "@/contexts/SettingsContext.tsx";
import { ManagementServerSwitch } from "@/components/ManagementServerSwitch.tsx";
import { ManagementMode, useManagementUrl } from "@/hooks/useManagementUrl.ts";
import { LanguagePicker } from "@/components/LanguagePicker.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

export function SettingsGeneral() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { autostart, setAutostartEnabled } = useAutostartSetting();
    const { mode, setMode, setUrl, displayUrl, showError, canSave, save, checking, unreachable } =
        useManagementUrl();
    const { mdm, features } = useRestrictions();

    const inputRef = useRef<HTMLInputElement>(null);
    const managementUrlId = useId();
    const prevMode = useRef(mode);
    useEffect(() => {
        if (prevMode.current === ManagementMode.Cloud && mode === ManagementMode.SelfHosted) {
            inputRef.current?.focus();
        }
        prevMode.current = mode;
    }, [mode]);

    return (
        <>
            <SectionGroup title={t("settings.general.section.general")}>
                <LanguagePicker />
                <FancyToggleSwitch
                    value={!config.disableNotifications}
                    onChange={(v) => setField("disableNotifications", !v)}
                    label={t("settings.general.notifications.label")}
                    helpText={t("settings.general.notifications.help")}
                />
                {!mdm.disableAutoConnect && !features.disableUpdateSettings && (
                    <FancyToggleSwitch
                        value={!config.disableAutoConnect}
                        onChange={(v) => setField("disableAutoConnect", !v)}
                        label={t("settings.general.connectOnStartup.label")}
                        helpText={t("settings.general.connectOnStartup.help")}
                    />
                )}
                {(autostart === null || autostart.supported) && (
                    <FancyToggleSwitch
                        value={autostart?.enabled ?? false}
                        onChange={setAutostartEnabled}
                        loading={autostart === null}
                        label={t("settings.general.autostart.label")}
                        helpText={t("settings.general.autostart.help")}
                    />
                )}
            </SectionGroup>

            {!mdm.managementURL && !features.disableUpdateSettings && (
                <SectionGroup title={t("settings.general.section.connection")}>
                    <div>
                        <div className={"flex items-start gap-3"}>
                            <div className={"min-w-0 flex-1"}>
                                <Label htmlFor={managementUrlId}>
                                    {t("settings.general.management.label")}
                                </Label>
                                <HelpText>{t("settings.general.management.help")}</HelpText>
                            </div>
                            <ManagementServerSwitch value={mode} onChange={setMode} />
                        </div>
                        {mode === ManagementMode.SelfHosted && (
                            <div className={"mt-2 flex items-start gap-3"}>
                                <Input
                                    id={managementUrlId}
                                    ref={inputRef}
                                    value={displayUrl}
                                    onChange={(e) => setUrl(e.target.value)}
                                    placeholder={t("settings.general.management.urlPlaceholder")}
                                    error={
                                        showError
                                            ? t("settings.general.management.urlError")
                                            : undefined
                                    }
                                    warning={
                                        unreachable
                                            ? t("settings.general.management.urlUnreachable")
                                            : undefined
                                    }
                                    spellCheck={false}
                                    autoComplete={"off"}
                                    autoCorrect={"off"}
                                    autoCapitalize={"off"}
                                />
                                <Button
                                    variant={"primary"}
                                    size={"md"}
                                    disabled={!canSave}
                                    loading={checking}
                                    onClick={() => save()}
                                >
                                    {t("common.save")}
                                </Button>
                            </div>
                        )}
                    </div>
                </SectionGroup>
            )}
        </>
    );
}
