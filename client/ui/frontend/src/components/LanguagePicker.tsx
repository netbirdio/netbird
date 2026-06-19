import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { CheckIcon, ChevronDown, LanguagesIcon, Search } from "lucide-react";
import { Preferences } from "@bindings/services";
import { type LanguageCode, type Language } from "@bindings/i18n/models.js";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { useFocusVisible } from "@/hooks/useFocusVisible";
import { loadLanguages } from "@/lib/i18n";
import { cn } from "@/lib/cn";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

// No flag icons: flags represent countries, not languages. https://www.flagsarenotlanguages.com/blog/

const labelFor = (lang: Language): string =>
    lang.englishName && lang.englishName !== lang.displayName
        ? `${lang.displayName} (${lang.englishName})`
        : lang.displayName;

export function LanguagePicker() {
    const { t, i18n } = useTranslation();
    const [languages, setLanguages] = useState<Language[]>([]);
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    const isFocusVisible = useFocusVisible();

    useEffect(() => {
        let cancelled = false;
        loadLanguages()
            .then((list) => {
                if (!cancelled) setLanguages(list);
            })
            .catch((err: unknown) => console.error("load languages failed", err));
        return () => {
            cancelled = true;
        };
    }, []);

    const sorted = useMemo(
        () => [...languages].sort((a, b) => a.displayName.localeCompare(b.displayName)),
        [languages],
    );

    const current = useMemo(
        () =>
            languages.find((l) => l.code === i18n.language) ??
            languages.find((l) => l.code === "en"),
        [languages, i18n.language],
    );

    const handleTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
        if (open) return;
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
        }
    };

    const select = async (code: string) => {
        setOpen(false);
        if (busy || code === i18n.language) return;
        setBusy(true);
        try {
            await Preferences.SetLanguage(code as LanguageCode);
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
                <Label as={"div"}>{t("settings.general.language.label")}</Label>
                <HelpText margin={false}>{t("settings.general.language.help")}</HelpText>
            </div>
            <div className={"shrink-0"}>
                <Popover.Root open={open} onOpenChange={setOpen}>
                    <Popover.Trigger asChild>
                        <button
                            type={"button"}
                            tabIndex={0}
                            disabled={busy || languages.length === 0}
                            onKeyDown={handleTriggerKeyDown}
                            aria-label={t("settings.general.language.label")}
                            aria-haspopup={"listbox"}
                            aria-expanded={open}
                            className={cn(
                                "inline-flex h-[40px] min-w-[240px] items-center gap-2 px-3",
                                "rounded-md border bg-white dark:bg-nb-gray-900",
                                "border-neutral-200 dark:border-nb-gray-700",
                                "cursor-default text-xs font-semibold text-nb-gray-100 outline-none",
                                "hover:border-nb-gray-600 data-[state=open]:border-nb-gray-600",
                                isFocusVisible &&
                                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                                "disabled:opacity-50",
                            )}
                        >
                            <LanguagesIcon
                                size={16}
                                aria-hidden={"true"}
                                className={"shrink-0 text-nb-gray-200"}
                            />
                            <span className={"flex-1 truncate text-left"}>
                                {current ? labelFor(current) : "—"}
                            </span>
                            <ChevronDown
                                size={12}
                                aria-hidden={"true"}
                                className={"shrink-0 text-nb-gray-400"}
                            />
                        </button>
                    </Popover.Trigger>

                    <Popover.Portal>
                        <Popover.Content
                            align={"start"}
                            sideOffset={6}
                            className={cn(
                                "w-[var(--radix-popover-trigger-width)]",
                                "z-50 rounded-lg border border-nb-gray-850 bg-nb-gray-920 p-1 shadow-lg",
                                "data-[side=bottom]:origin-top data-[side=top]:origin-bottom",
                                "data-[state=open]:animate-in",
                                "data-[state=open]:fade-in-0",
                                "data-[state=open]:zoom-in-95",
                                "data-[side=bottom]:slide-in-from-top-1",
                                "data-[side=top]:slide-in-from-bottom-1",
                                "duration-150 ease-out",
                            )}
                        >
                            <Command
                                loop
                                className={cn(
                                    "flex flex-col",
                                    "[&_[cmdk-input-wrapper]]:flex [&_[cmdk-input-wrapper]]:items-center",
                                )}
                            >
                                <div className={"px-1 pb-1"}>
                                    <div
                                        role={"search"}
                                        className={"group flex h-8 items-center gap-2 px-1"}
                                    >
                                        <Search
                                            size={14}
                                            aria-hidden={"true"}
                                            className={"shrink-0 text-nb-gray-200"}
                                        />
                                        <Command.Input
                                            autoFocus
                                            placeholder={t("settings.general.language.search")}
                                            aria-label={t("settings.general.language.search")}
                                            className={cn(
                                                "w-full bg-transparent text-xs text-nb-gray-100 placeholder:text-nb-gray-300",
                                                "border-none outline-none",
                                            )}
                                        />
                                    </div>
                                </div>

                                <ScrollArea.Root type={"auto"} className={"-mx-1 overflow-hidden"}>
                                    <ScrollArea.Viewport className={"max-h-64 px-1"}>
                                        <Command.List>
                                            <Command.Empty>
                                                <div
                                                    className={
                                                        "px-3 py-4 text-center text-[0.7rem] text-nb-gray-400"
                                                    }
                                                >
                                                    {t("settings.general.language.empty")}
                                                </div>
                                            </Command.Empty>

                                            {sorted.map((lang) => {
                                                const checked = lang.code === i18n.language;
                                                return (
                                                    <Command.Item
                                                        key={lang.code}
                                                        value={`${lang.displayName} ${lang.englishName} ${lang.code}`}
                                                        onSelect={() => void select(lang.code)}
                                                        className={cn(
                                                            "my-0.5 flex cursor-default items-center gap-2 rounded-md px-2 py-2 outline-none",
                                                            "text-xs font-semibold text-nb-gray-200",
                                                            "data-[selected=true]:bg-nb-gray-850 data-[selected=true]:text-nb-gray-50",
                                                        )}
                                                    >
                                                        <span className={"min-w-0 flex-1 truncate"}>
                                                            {labelFor(lang)}
                                                        </span>
                                                        <span
                                                            aria-hidden={"true"}
                                                            className={
                                                                "flex w-4 shrink-0 items-center justify-center"
                                                            }
                                                        >
                                                            {checked && (
                                                                <CheckIcon
                                                                    size={14}
                                                                    className={"text-netbird"}
                                                                />
                                                            )}
                                                        </span>
                                                    </Command.Item>
                                                );
                                            })}
                                        </Command.List>
                                    </ScrollArea.Viewport>
                                    <ScrollArea.Scrollbar
                                        orientation={"vertical"}
                                        className={cn(
                                            "flex touch-none select-none transition-colors",
                                            "w-1.5 bg-transparent py-1",
                                        )}
                                    >
                                        <ScrollArea.Thumb
                                            className={
                                                "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
                                            }
                                        />
                                    </ScrollArea.Scrollbar>
                                </ScrollArea.Root>
                            </Command>
                        </Popover.Content>
                    </Popover.Portal>
                </Popover.Root>
            </div>
        </div>
    );
}
