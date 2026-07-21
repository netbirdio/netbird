import { useTranslation } from "react-i18next";
import { AlertCircleIcon, BookText } from "lucide-react";
import { Browser } from "@wailsio/runtime";
import { Button } from "@/components/buttons/Button";
import { useStatus } from "@/contexts/StatusContext.tsx";

const DOCS_URL = "https://docs.netbird.io/how-to/installation";

function openUrl(url: string) {
    Browser.OpenURL(url).catch(() => globalThis.open(url, "_blank"));
}

export const DaemonUnavailableOverlay = () => {
    const { t } = useTranslation();
    const { isDaemonUnavailable } = useStatus();

    if (!isDaemonUnavailable) return null;

    return (
        <div
            className={
                "wails-draggable fixed inset-0 z-[100] flex cursor-default select-none items-center justify-center bg-nb-gray-950 backdrop-blur-sm"
            }
        >
            <div className={"flex max-w-lg flex-col items-center gap-5 px-8 text-center"}>
                <div
                    className={
                        "flex h-11 w-11 items-center justify-center rounded-xl border border-nb-gray-900 bg-nb-gray-920 text-red-500"
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
