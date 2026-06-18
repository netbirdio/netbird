import { useTranslation } from "react-i18next";
import { AlertTriangleIcon, DownloadIcon } from "lucide-react";
import { Browser } from "@wailsio/runtime";
import { Button } from "@/components/buttons/Button";
import { useStatus } from "@/contexts/StatusContext.tsx";

const RELEASES_URL = "https://github.com/netbirdio/netbird/releases/latest";

function openUrl(url: string) {
    Browser.OpenURL(url).catch(() => globalThis.open(url, "_blank"));
}

export const DaemonOutdatedOverlay = () => {
    const { t } = useTranslation();
    const { isDaemonOutdated } = useStatus();

    if (!isDaemonOutdated) return null;

    return (
        <div
            className={"fixed inset-0 z-[100] flex items-center justify-center bg-nb-gray-950 backdrop-blur-sm cursor-default select-none wails-draggable"}
        >
            <div className={"flex flex-col items-center gap-5 px-8 max-w-lg text-center"}>
                <div
                    className={"h-11 w-11 rounded-xl flex items-center justify-center bg-nb-gray-920 border border-nb-gray-900 text-amber-500"}
                >
                    <AlertTriangleIcon size={20} />
                </div>

                <div className={"flex flex-col items-center gap-1"}>
                    <p className={"text-base font-medium text-nb-gray-50"}>
                        {t("daemon.outdated.title")}
                    </p>
                    <p className={"text-sm text-nb-gray-300"}>{t("daemon.outdated.description")}</p>
                </div>

                <div className={"wails-no-draggable"}>
                    <Button variant={"primary"} size={"xs"} onClick={() => openUrl(RELEASES_URL)}>
                        <DownloadIcon size={14} />
                        {t("update.card.getInstaller")}
                    </Button>
                </div>
            </div>
        </div>
    );
};
