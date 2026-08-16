import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { BanIcon, CheckIcon, XIcon } from "lucide-react";
import { FileDrop } from "@bindings/services";
import { FileDropSettings } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { PeerRule, ReceiveMode } from "@/lib/filedrop";
import { shortenDns } from "@/lib/formatters";
import { Button } from "@/components/buttons/Button";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import { useStatus } from "@/contexts/StatusContext";

const MODES: { value: ReceiveMode; labelKey: string; helpKey: string }[] = [
    {
        value: ReceiveMode.Off,
        labelKey: "settings.fileSharing.mode.off",
        helpKey: "settings.fileSharing.mode.off.help",
    },
    {
        value: ReceiveMode.Ask,
        labelKey: "settings.fileSharing.mode.ask",
        helpKey: "settings.fileSharing.mode.ask.help",
    },
    {
        value: ReceiveMode.Auto,
        labelKey: "settings.fileSharing.mode.auto",
        helpKey: "settings.fileSharing.mode.auto.help",
    },
];

export function SettingsFileSharing() {
    const { t } = useTranslation();
    const { status } = useStatus();
    const [settings, setSettings] = useState<FileDropSettings | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        FileDrop.GetSettings()
            .then(setSettings)
            .catch((e: unknown) => setError(String(e)));
    }, []);

    const apply = useCallback(
        async (next: FileDropSettings) => {
            const prev = settings;
            setSettings(next);
            try {
                await FileDrop.SetSettings(next);
                setError(null);
            } catch (e) {
                setSettings(prev);
                setError(String(e));
            }
        },
        [settings],
    );

    const changeDirectory = async () => {
        if (!settings) return;
        const dir = await FileDrop.PickDirectory();
        if (!dir) return;
        await apply(new FileDropSettings({ ...settings, destinationDir: dir }));
    };

    const removeRule = async (peerKey: string) => {
        if (!settings) return;
        try {
            await FileDrop.SetPeerRule(peerKey, PeerRule.Default);
            setSettings(await FileDrop.GetSettings());
        } catch (e) {
            setError(String(e));
        }
    };

    const peerName = (key: string): string => {
        const peer = (status?.peers ?? []).find((p) => p.pubKey === key);
        return peer ? shortenDns(peer.fqdn) || peer.ip : key.slice(0, 12) + "…";
    };

    if (!settings) {
        return (
            <SectionGroup title={t("settings.fileSharing.section")}>
                <HelpText>{error ?? t("settings.fileSharing.loading")}</HelpText>
            </SectionGroup>
        );
    }

    const rules = Object.entries(settings.peerRules ?? {});

    return (
        <SectionGroup title={t("settings.fileSharing.section")}>
            {error && <HelpText className={"text-red-400"}>{error}</HelpText>}
            <div>
                <Label>{t("settings.fileSharing.mode.label")}</Label>
                <HelpText>{t("settings.fileSharing.mode.help")}</HelpText>
                <div
                    role={"radiogroup"}
                    aria-label={t("settings.fileSharing.mode.label")}
                    className={"mt-2 flex flex-col gap-1.5"}
                >
                    {MODES.map((mode) => {
                        const active = settings.mode === mode.value;
                        return (
                            <button
                                key={mode.value}
                                type={"button"}
                                role={"radio"}
                                aria-checked={active}
                                onClick={() =>
                                    void apply(
                                        new FileDropSettings({ ...settings, mode: mode.value }),
                                    )
                                }
                                className={cn(
                                    "flex items-center gap-3 rounded-lg border px-4 py-3 text-left",
                                    "cursor-default outline-none transition-colors",
                                    "focus-visible:ring-2 focus-visible:ring-white/60",
                                    active
                                        ? "border-netbird/60 bg-netbird/5"
                                        : "border-nb-gray-900 hover:border-nb-gray-800",
                                )}
                            >
                                <span
                                    aria-hidden={"true"}
                                    className={cn(
                                        "flex h-4 w-4 shrink-0 items-center justify-center rounded-full border",
                                        active ? "border-netbird bg-netbird" : "border-nb-gray-600",
                                    )}
                                >
                                    {active && <CheckIcon size={11} className={"text-white"} />}
                                </span>
                                <span className={"flex flex-col leading-tight"}>
                                    <span className={"text-sm text-nb-gray-100"}>
                                        {t(mode.labelKey)}
                                    </span>
                                    <span className={"text-xs text-nb-gray-400"}>
                                        {t(mode.helpKey)}
                                    </span>
                                </span>
                            </button>
                        );
                    })}
                </div>
            </div>
            <div>
                <Label>{t("settings.fileSharing.destination.label")}</Label>
                <HelpText>{t("settings.fileSharing.destination.help")}</HelpText>
                <div className={"mt-2 flex items-center gap-3"}>
                    <span
                        className={cn(
                            "min-w-0 flex-1 truncate rounded-md border border-nb-gray-900",
                            "px-3 py-2 font-mono text-xs text-nb-gray-300",
                        )}
                    >
                        {settings.destinationDir || t("settings.fileSharing.destination.unset")}
                    </span>
                    <Button
                        variant={"secondary"}
                        size={"xs"}
                        onClick={() => void changeDirectory()}
                    >
                        {t("settings.fileSharing.destination.change")}
                    </Button>
                </div>
            </div>
            <div>
                <Label>{t("settings.fileSharing.exceptions.label")}</Label>
                <HelpText>{t("settings.fileSharing.exceptions.help")}</HelpText>
                {rules.length === 0 ? (
                    <HelpText className={"mt-2"}>
                        {t("settings.fileSharing.exceptions.empty")}
                    </HelpText>
                ) : (
                    <ul className={"mt-2 flex flex-col divide-y divide-nb-gray-920"}>
                        {rules.map(([key, rule]) => (
                            <li key={key} className={"flex items-center gap-3 py-2"}>
                                {rule === PeerRule.Block ? (
                                    <BanIcon
                                        size={14}
                                        className={"shrink-0 text-red-400"}
                                        aria-hidden={"true"}
                                    />
                                ) : (
                                    <CheckIcon
                                        size={14}
                                        className={"shrink-0 text-green-400"}
                                        aria-hidden={"true"}
                                    />
                                )}
                                <span
                                    className={"min-w-0 flex-1 truncate text-sm text-nb-gray-100"}
                                >
                                    {peerName(key)}
                                </span>
                                <span className={"shrink-0 text-xs text-nb-gray-400"}>
                                    {rule === PeerRule.Block
                                        ? t("settings.fileSharing.exceptions.blocked")
                                        : t("settings.fileSharing.exceptions.always")}
                                </span>
                                <button
                                    type={"button"}
                                    aria-label={t("settings.fileSharing.exceptions.remove")}
                                    onClick={() => void removeRule(key)}
                                    className={cn(
                                        "flex h-6 w-6 shrink-0 items-center justify-center rounded-md",
                                        "text-nb-gray-400 hover:bg-nb-gray-900 hover:text-nb-gray-100",
                                        "cursor-default outline-none transition-colors",
                                        "focus-visible:ring-2 focus-visible:ring-white/60",
                                    )}
                                >
                                    <XIcon size={13} />
                                </button>
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </SectionGroup>
    );
}
