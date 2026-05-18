import { useTranslation } from "react-i18next";
import { AlertCircleIcon, AlertTriangle, BookText } from "lucide-react";
import { Browser } from "@wailsio/runtime";
import { Button } from "@/components/Button";
import { useStatus } from "@/hooks/useStatus";

const DOCS_URL = "https://docs.netbird.io/how-to/installation";

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
}

export const DaemonUnavailableOverlay = () => {
    const { t } = useTranslation();
    const { status } = useStatus();

    if (status?.status !== "DaemonUnavailable") return null;

    return (
        <div
            className={
                "fixed inset-0 z-[100] flex items-center justify-center bg-nb-gray-950 backdrop-blur-sm cursor-default select-none wails-draggable"
            }
            onKeyDown={(e) => {
                e.preventDefault();
                e.stopPropagation();
            }}
        >
            <div className={"flex flex-col items-center gap-5 px-8 max-w-lg text-center"}>
                <div
                    className={
                        "h-11 w-11 rounded-xl flex items-center justify-center bg-nb-gray-920 border border-nb-gray-900 text-red-500"
                    }
                >
                    <AlertCircleIcon size={20} />
                </div>

                <div className={"flex flex-col items-center gap-1"}>
                    <p className={"text-base font-medium text-nb-gray-50"}>
                        {t("daemon.unavailable.title")}
                    </p>
                    <p className={"text-sm text-nb-gray-300"}>
                        {t("daemon.unavailable.description")}
                    </p>
                </div>

                <div className={"wails-no-draggable"}>
                    <Button variant={"secondary"} size={"xs"} onClick={() => openUrl(DOCS_URL)}>
                        <BookText size={14} />
                        {t("daemon.unavailable.docsLink")}
                    </Button>
                </div>
            </div>
        </div>
    );
};
