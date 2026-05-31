import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Dialogs } from "@wailsio/runtime";
import { Button } from "@/components/buttons/Button";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { ManagementServerSwitch } from "@/components/ManagementServerSwitch.tsx";
import { ManagementMode, useManagementUrl } from "@/hooks/useManagementUrl.ts";
import { LanguagePicker } from "@/components/LanguagePicker.tsx";
import { Autostart } from "@bindings/services";
import i18next from "@/lib/i18n";

export function SettingsGeneral() {
    const { t } = useTranslation();
    const { config, setField } = useSettings();
    const { mode, setMode, setUrl, displayUrl, showError, canSave, save } = useManagementUrl();

    // Autostart lives in the OS login-item registry, not the daemon config, so
    // it has its own read-on-mount state. supported gates whether we render the
    // toggle at all (false on server/mobile builds).
    const [autostartSupported, setAutostartSupported] = useState(false);
    const [autostartEnabled, setAutostartEnabled] = useState(false);
    useEffect(() => {
        let cancelled = false;
        (async () => {
            const supported = await Autostart.Supported();
            if (cancelled) return;
            setAutostartSupported(supported);
            if (!supported) return;
            setAutostartEnabled(await Autostart.IsEnabled());
        })().catch(() => {});
        return () => {
            cancelled = true;
        };
    }, []);

    const onAutostartChange = async (enabled: boolean) => {
        setAutostartEnabled(enabled);
        try {
            await Autostart.SetEnabled(enabled);
        } catch (e) {
            setAutostartEnabled(!enabled);
            await Dialogs.Error({
                Title: i18next.t("settings.general.autostart.errorTitle"),
                Message: String(e),
            });
        }
    };

    const inputRef = useRef<HTMLInputElement>(null);
    const prevMode = useRef(mode);
    useEffect(() => {
        if (
            prevMode.current === ManagementMode.Cloud &&
            mode === ManagementMode.SelfHosted
        ) {
            inputRef.current?.focus();
        }
        prevMode.current = mode;
    }, [mode]);

    return (
        <>
            <SectionGroup title={t("settings.general.section.general")}>
                <LanguagePicker />
                <FancyToggleSwitch
                    value={!config.disableAutoConnect}
                    onChange={(v) => setField("disableAutoConnect", !v)}
                    label={t("settings.general.connectOnStartup.label")}
                    helpText={t("settings.general.connectOnStartup.help")}
                />
                <FancyToggleSwitch
                    value={!config.disableNotifications}
                    onChange={(v) => setField("disableNotifications", !v)}
                    label={t("settings.general.notifications.label")}
                    helpText={t("settings.general.notifications.help")}
                />
                {autostartSupported && (
                    <FancyToggleSwitch
                        value={autostartEnabled}
                        onChange={onAutostartChange}
                        label={t("settings.general.autostart.label")}
                        helpText={t("settings.general.autostart.help")}
                    />
                )}
            </SectionGroup>

            <SectionGroup title={t("settings.general.section.connection")}>
                <div>
                    <div className={"flex items-start gap-3"}>
                        <div className={"flex-1 min-w-0"}>
                            <Label as={"div"}>{t("settings.general.management.label")}</Label>
                            <HelpText>
                                {t("settings.general.management.help")}
                            </HelpText>
                        </div>
                        <ManagementServerSwitch value={mode} onChange={setMode} />
                    </div>
                    {mode === ManagementMode.SelfHosted && (
                        <div className={"flex items-start gap-3 mt-2"}>
                            <Input
                                ref={inputRef}
                                value={displayUrl}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder={t("settings.general.management.urlPlaceholder")}
                                error={
                                    showError
                                        ? t("settings.general.management.urlError")
                                        : undefined
                                }
                            />
                            <Button
                                variant={"primary"}
                                size={"md"}
                                disabled={!canSave}
                                onClick={() => save()}
                            >
                                {t("common.save")}
                            </Button>
                        </div>
                    )}
                </div>
            </SectionGroup>
        </>
    );
}
