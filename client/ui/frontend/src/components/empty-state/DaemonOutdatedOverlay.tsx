import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangleIcon, DownloadIcon } from "lucide-react";
import { Browser } from "@wailsio/runtime";
import { Version } from "@bindings/services";
import { Button } from "@/components/buttons/Button";
import { useStatus } from "@/contexts/StatusContext.tsx";

const RELEASES_URL = "https://github.com/netbirdio/netbird/releases/latest";
const RC_RELEASES_URL = "https://pkgs.netbird.io/releases/rc";

function openUrl(url: string) {
    Browser.OpenURL(url).catch(() => globalThis.open(url, "_blank"));
}

export const DaemonOutdatedOverlay = () => {
    const { t } = useTranslation();
    const { status, isDaemonOutdated } = useStatus();

    const [guiVersion, setGuiVersion] = useState<string>("-");
    const clientVersion = status?.daemonVersion ?? "—";

    const isRc = /-rc/i.test(guiVersion) || /-rc/i.test(clientVersion);
    const downloadUrl = isRc ? RC_RELEASES_URL : RELEASES_URL;

    useEffect(() => {
        if (!isDaemonOutdated) return;
        let cancelled = false;
        Version.GUI()
            .then((v) => {
                if (!cancelled) setGuiVersion(v);
            })
            .catch((err) => console.error("[DaemonOutdatedOverlay] GUI version error", err));
        return () => {
            cancelled = true;
        };
    }, [isDaemonOutdated]);

    if (!isDaemonOutdated) return null;

    return (
        <div
            className={
                "wails-draggable fixed inset-0 z-[100] flex cursor-default select-none items-center justify-center bg-nb-gray-950 backdrop-blur-sm"
            }
        >
            <div className={"flex max-w-lg flex-col items-center gap-5 px-8 text-center"}>
                <div
                    className={
                        "flex h-11 w-11 items-center justify-center rounded-xl border border-nb-gray-900 bg-nb-gray-920 text-amber-500"
                    }
                >
                    <AlertTriangleIcon size={20} />
                </div>

                <div className={"flex flex-col items-center gap-1"}>
                    <p className={"text-base font-medium text-nb-gray-50"}>
                        {t("daemon.outdated.title")}
                    </p>
                    <p className={"text-sm text-nb-gray-300"}>{t("daemon.outdated.description")}</p>
                </div>

                <div className={"flex flex-col items-center gap-0.5 text-center"}>
                    <p className={"text-sm font-semibold text-nb-gray-100"}>
                        {clientVersion === "development" ? (
                            <span>
                                {t("settings.about.clientName")}{" "}
                                <span className={"font-mono text-yellow-400"}>
                                    {t("settings.about.development")}
                                </span>
                            </span>
                        ) : (
                            t("settings.about.client", { version: clientVersion })
                        )}
                    </p>
                    <p className={"text-sm font-medium text-nb-gray-250"}>
                        {guiVersion === "development" ? (
                            <span>
                                {t("settings.about.guiName")}{" "}
                                <span className={"font-mono text-yellow-400"}>
                                    {t("settings.about.development")}
                                </span>
                            </span>
                        ) : (
                            t("settings.about.gui", { version: guiVersion })
                        )}
                    </p>
                </div>

                <div className={"wails-no-draggable"}>
                    <Button variant={"primary"} size={"xs"} onClick={() => openUrl(downloadUrl)}>
                        <DownloadIcon size={14} />
                        {t("daemon.outdated.download")}
                    </Button>
                </div>
            </div>
        </div>
    );
};
