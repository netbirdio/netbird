import { useTranslation } from "react-i18next";
import { Browser } from "@wailsio/runtime";
import netbirdFull from "@/assets/logos/netbird-full.svg";
import pkg from "../../../package.json";
import { useStatus } from "@/modules/daemon-status/StatusContext.tsx";
import { UpdateVersionCard } from "@/modules/auto-update/UpdateVersionCard";
import { useAccentTrigger } from "@/modules/settings/SettingsAccent";

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
}

export function SettingsAbout() {
    const { t } = useTranslation();
    const { status } = useStatus();
    const guiVersion = pkg.version;
    const daemonVersion = status?.daemonVersion ?? "—";

    const handleVersionClick = useAccentTrigger();

    const LEGAL_LINKS: { label: string; url: string }[] = [
        { label: t("settings.about.links.imprint"), url: "https://netbird.io/imprint" },
        { label: t("settings.about.links.privacy"), url: "https://netbird.io/privacy" },
        { label: t("settings.about.links.cla"), url: "https://netbird.io/cla" },
        { label: t("settings.about.links.terms"), url: "https://netbird.io/terms" },
    ];

    return (
        <div
            className={
                "flex flex-col items-center justify-center gap-4 max-w-2xl mx-auto min-h-[calc(100vh-10rem)]"
            }
        >
            <img src={netbirdFull} alt={"NetBird"} className={"h-7 w-auto"} />
            <div className={"flex flex-col items-center gap-0.5 text-center"}>
                <p
                    className={"text-sm font-semibold text-nb-gray-100 cursor-default select-none"}
                    onClick={handleVersionClick}
                >
                    {daemonVersion === "development" ? (
                        <span>
                            {t("settings.about.clientName")}{" "}
                            <span className={" text-yellow-400 font-mono"}>
                                {t("settings.about.development")}
                            </span>
                        </span>
                    ) : (
                        t("settings.about.client", { version: daemonVersion })
                    )}
                </p>
                <p className={"text-sm text-nb-gray-300"}>
                    {t("settings.about.gui", { version: guiVersion })}
                </p>
            </div>

            <UpdateVersionCard />

            <p className={"text-sm text-nb-gray-300 text-center"}>
                {t("settings.about.copyright", { year: new Date().getFullYear() })}
            </p>
            <div
                className={"flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs text-nb-gray-200"}
            >
                {LEGAL_LINKS.map((link) => (
                    <button
                        key={link.url}
                        type={"button"}
                        onClick={() => openUrl(link.url)}
                        className={
                            "decoration-[0.5px] underline-offset-4 hover:text-nb-gray-100 hover:underline transition"
                        }
                    >
                        {link.label}
                    </button>
                ))}
            </div>
        </div>
    );
}
