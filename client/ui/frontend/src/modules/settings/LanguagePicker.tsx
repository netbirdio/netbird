import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { Dialogs } from "@wailsio/runtime";
import { CheckIcon, ChevronDown, Search } from "lucide-react";
import { Preferences } from "@bindings/services";
import { LanguageCode, type Language } from "@bindings/i18n/models.js";
import { HelpText } from "@/components/HelpText";
import { Label } from "@/components/Label";
import { loadLanguages } from "@/lib/i18n";
import { cn } from "@/lib/cn";

// Flags live alongside the rest of the SVG flag library under
// assets/flags/1x1 and are filename-matched to the language code
// (de → de.svg, en → en.svg, hu → hu.svg). Vite eager-globs them at
// build time; the JS bundle only holds URL refs, not the SVG bytes.
const FLAG_URLS = import.meta.glob<string>("@/assets/flags/1x1/*.svg", {
    eager: true,
    import: "default",
    query: "?url",
});

const flagByCode: Record<string, string> = {};
for (const path in FLAG_URLS) {
    const match = path.match(/1x1\/([^/]+)\.svg$/);
    if (match) flagByCode[match[1]] = FLAG_URLS[path];
}

const flagFor = (code: string): string | undefined => flagByCode[code.toLowerCase().split("-")[0]];

function Flag({ code, label }: { code: string; label: string }) {
    const src = flagFor(code);
    if (!src) {
        return (
            <span
                className={"h-3.5 w-3.5 rounded-full bg-nb-gray-800 shrink-0 inline-block"}
                aria-hidden
            />
        );
    }
    return (
        <img
            src={src}
            alt={label}
            className={"h-3.5 w-3.5 rounded-full object-cover shrink-0 select-none"}
            draggable={false}
        />
    );
}

export function LanguagePicker() {
    const { t, i18n } = useTranslation();
    const [languages, setLanguages] = useState<Language[]>([]);
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        let cancelled = false;
        loadLanguages()
            .then((list) => {
                if (!cancelled) setLanguages(list);
            })
            .catch(() => {});
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

    const select = async (code: string) => {
        if (busy || code === i18n.language) {
            setOpen(false);
            return;
        }
        setBusy(true);
        try {
            await Preferences.SetLanguage(code as LanguageCode);
        } catch (e) {
            await Dialogs.Error({
                Title: t("settings.error.saveTitle"),
                Message: e instanceof Error ? e.message : String(e),
            });
        } finally {
            setBusy(false);
            setOpen(false);
        }
    };

    return (
        <div className={"flex items-center gap-6 justify-between"}>
            <div className={"flex-1 max-w-md"}>
                <Label as={"div"}>{t("settings.general.language.label")}</Label>
                <HelpText margin={false}>{t("settings.general.language.help")}</HelpText>
            </div>
            <div className={"shrink-0"}>
                <Popover.Root open={open} onOpenChange={setOpen}>
                    <Popover.Trigger asChild>
                        <button
                            type={"button"}
                            disabled={busy || languages.length === 0}
                            className={cn(
                                "inline-flex items-center gap-2 h-[40px] px-3 min-w-[240px]",
                                "rounded-md border bg-white dark:bg-nb-gray-900",
                                "border-neutral-200 dark:border-nb-gray-700",
                                "text-xs font-semibold text-nb-gray-100 cursor-default outline-none",
                                "hover:border-nb-gray-600 data-[state=open]:border-nb-gray-600",
                                "disabled:opacity-50",
                            )}
                        >
                            {current && <Flag code={current.code} label={current.displayName} />}
                            <span className={"truncate flex-1 text-left"}>
                                {current?.displayName ?? "—"}
                            </span>
                            <ChevronDown size={12} className={"text-nb-gray-400 shrink-0"} />
                        </button>
                    </Popover.Trigger>

                    <Popover.Portal>
                        <Popover.Content
                            align={"start"}
                            sideOffset={6}
                            onCloseAutoFocus={(e) => e.preventDefault()}
                            className={cn(
                                "w-[var(--radix-popover-trigger-width)]",
                                "rounded-md border border-nb-gray-850 bg-nb-gray-920 shadow-lg p-1 z-50",
                                "origin-[var(--radix-popover-content-transform-origin)]",
                                "data-[state=open]:animate-in data-[state=closed]:animate-out",
                                "data-[state=open]:fade-in-0 data-[state=closed]:fade-out-0",
                                "data-[state=open]:zoom-in-95 data-[state=closed]:zoom-out-95",
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
                                    <div className={"group flex items-center gap-2 px-1 h-8"}>
                                        <Search size={14} className={"text-nb-gray-200 shrink-0"} />
                                        <Command.Input
                                            autoFocus
                                            placeholder={t("settings.general.language.search")}
                                            className={cn(
                                                "w-full bg-transparent text-xs text-nb-gray-100 placeholder:text-nb-gray-300",
                                                "outline-none border-none",
                                            )}
                                        />
                                    </div>
                                </div>

                                <ScrollArea.Root type={"auto"} className={"overflow-hidden -mx-1"}>
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
                                                            "flex items-center gap-2 px-2 py-2 rounded-md cursor-default outline-none my-0.5",
                                                            "text-xs font-semibold text-nb-gray-200",
                                                            "data-[selected=true]:bg-nb-gray-900 data-[selected=true]:text-nb-gray-50",
                                                        )}
                                                    >
                                                        <Flag
                                                            code={lang.code}
                                                            label={lang.displayName}
                                                        />
                                                        <span className={"flex-1 truncate"}>
                                                            {lang.displayName}
                                                        </span>
                                                        <span
                                                            className={
                                                                "w-4 shrink-0 flex items-center justify-center"
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
                                            "flex select-none touch-none transition-colors",
                                            "w-1.5 bg-transparent py-1",
                                        )}
                                    >
                                        <ScrollArea.Thumb
                                            className={
                                                "flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative"
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
