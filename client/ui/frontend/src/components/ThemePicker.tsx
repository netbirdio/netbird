import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronDown, MonitorIcon, MoonIcon, SunMediumIcon, type LucideIcon } from "lucide-react";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuRadioGroup,
    DropdownMenuRadioItem,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { useTheme, type ThemePreference } from "@/contexts/ThemeContext";
import { useFocusVisible } from "@/hooks/useFocusVisible";
import { cn } from "@/lib/cn";
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
    const isFocusVisible = useFocusVisible();

    const current = OPTIONS.find((o) => o.value === theme) ?? OPTIONS[0];
    const CurrentIcon = current.icon;

    const select = async (value: string) => {
        if (busy || value === theme) return;
        setBusy(true);
        try {
            await setTheme(value as ThemePreference);
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
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <button
                            type={"button"}
                            tabIndex={0}
                            disabled={busy}
                            aria-label={t("settings.general.theme.label")}
                            className={cn(
                                "inline-flex h-[40px] min-w-[160px] items-center gap-2 px-3",
                                "rounded-md border bg-white dark:bg-nb-gray-900",
                                "border-neutral-200 dark:border-nb-gray-700",
                                "cursor-default text-xs font-semibold text-nb-gray-100 outline-none",
                                "hover:border-nb-gray-600 data-[state=open]:border-nb-gray-600",
                                isFocusVisible &&
                                    "focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                                "disabled:opacity-50",
                            )}
                        >
                            <CurrentIcon
                                size={16}
                                aria-hidden={"true"}
                                className={"shrink-0 text-nb-gray-200"}
                            />
                            <span className={"flex-1 truncate text-left"}>
                                {t(current.labelKey)}
                            </span>
                            <ChevronDown
                                size={12}
                                aria-hidden={"true"}
                                className={"shrink-0 text-nb-gray-400"}
                            />
                        </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent
                        align={"end"}
                        className={"w-[var(--radix-dropdown-menu-trigger-width)]"}
                    >
                        <DropdownMenuRadioGroup value={theme} onValueChange={(v) => void select(v)}>
                            {OPTIONS.map(({ value, icon: Icon, labelKey }) => (
                                <DropdownMenuRadioItem key={value} value={value}>
                                    <Icon
                                        size={14}
                                        aria-hidden={"true"}
                                        className={"mr-2 shrink-0 text-nb-gray-300"}
                                    />
                                    {t(labelKey)}
                                </DropdownMenuRadioItem>
                            ))}
                        </DropdownMenuRadioGroup>
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>
        </div>
    );
}
