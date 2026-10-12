import { useState } from "react";
import { useTranslation } from "react-i18next";
import { MonitorIcon, MoonIcon, SunMediumIcon, type LucideIcon } from "lucide-react";
import { Select } from "@/components/inputs/Select";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { useTheme, type ThemePreference } from "@/contexts/ThemeContext";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

const OPTIONS: { value: ThemePreference; icon: LucideIcon; labelKey: string }[] = [
    { value: "system", icon: MonitorIcon, labelKey: "settings.general.theme.system" },
    { value: "light", icon: SunMediumIcon, labelKey: "settings.general.theme.light" },
    { value: "dark", icon: MoonIcon, labelKey: "settings.general.theme.dark" },
];

export function ThemePicker() {
    const { t } = useTranslation();
    const { theme, setTheme } = useTheme();
    const [busy, setBusy] = useState(false);

    const select = async (value: ThemePreference) => {
        if (busy || value === theme) return;
        setBusy(true);
        try {
            await setTheme(value);
        } catch (e) {
            await errorDialog({
                Title: t("settings.error.saveTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className={"flex items-center justify-between gap-6"}>
            <div className={"max-w-md flex-1"}>
                <Label as={"div"}>{t("settings.general.theme.label")}</Label>
                <HelpText margin={false}>{t("settings.general.theme.help")}</HelpText>
            </div>
            <div className={"shrink-0"}>
                <Select
                    value={theme}
                    options={OPTIONS.map(({ value, icon, labelKey }) => ({
                        value,
                        icon,
                        label: t(labelKey),
                    }))}
                    onChange={(v) => void select(v)}
                    ariaLabel={t("settings.general.theme.label")}
                    disabled={busy}
                />
            </div>
        </div>
    );
}
