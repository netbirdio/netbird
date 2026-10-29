import { type ReactNode, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Browser } from "@wailsio/runtime";
import { DownloadIcon, NotepadText } from "lucide-react";
import { Update as UpdateSvc } from "@bindings/services";
import { Button } from "@/components/buttons/Button";
import { useClientVersion } from "@/contexts/ClientVersionContext";
import { cn } from "@/lib/cn";

const GITHUB_RELEASES = "https://github.com/netbirdio/netbird/releases/latest";

function openUrl(url: string) {
    Browser.OpenURL(url).catch(() => {
        window.open(url, "_blank");
    });
}

// useInstallerUrl resolves the installer download link. It is empty for a
// named installation, which the upstream installer cannot update, so no
// download is offered there.
function useInstallerUrl(): string | null {
    const [url, setUrl] = useState<string | null>(null);
    useEffect(() => {
        UpdateSvc.DownloadURL()
            .then(setUrl)
            .catch(() => setUrl(GITHUB_RELEASES));
    }, []);
    return url;
}

export function UpdateVersionCard() {
    const { t } = useTranslation();
    const { updateVersion, enforced, triggerUpdate } = useClientVersion();
    const installerUrl = useInstallerUrl();

    if (updateVersion) {
        const titleKey = enforced
            ? "update.card.versionAvailableInstall"
            : "update.card.versionAvailableDownload";
        return (
            <Card className={"max-w-lg"}>
                <div>
                    <Title>{t(titleKey, { version: updateVersion })}</Title>
                    <Link
                        url={`https://github.com/netbirdio/netbird/releases/tag/v${updateVersion}`}
                    >
                        {t("update.card.whatsNew")}
                    </Link>
                </div>
                {enforced ? (
                    <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                        {t("update.card.installNow")}
                    </Button>
                ) : installerUrl ? (
                    <Button variant={"primary"} size={"xs"} onClick={() => openUrl(installerUrl)}>
                        <DownloadIcon size={14} />
                        {t("update.card.getInstaller")}
                    </Button>
                ) : null}
            </Card>
        );
    }

    return (
        <Card className={"max-w-lg"}>
            <div>
                <Title>{t("update.card.onLatestVersion")}</Title>
                <p className={"text-sm text-nb-gray-300"}>{t("update.card.autoCheckInterval")}</p>
            </div>
            <Button variant={"primary"} size={"xs"} onClick={() => openUrl(GITHUB_RELEASES)}>
                <NotepadText size={14} />
                {t("update.card.changelog")}
            </Button>
        </Card>
    );
}

function Card({ children, className }: Readonly<{ children: ReactNode; className?: string }>) {
    return (
        <div
            className={cn(
                "flex w-full items-center justify-between gap-4 rounded-md border border-nb-gray-800 bg-nb-gray-910 px-4 py-3",
                className,
            )}
        >
            {children}
        </div>
    );
}

function Title({ children }: Readonly<{ children: ReactNode }>) {
    return <p className={"text-sm font-semibold"}>{children}</p>;
}

function Link({ url, children }: Readonly<{ url: string; children: ReactNode }>) {
    return (
        <button
            type={"button"}
            onClick={() => openUrl(url)}
            className={
                "text-sm font-medium text-netbird hover:underline hover:decoration-[0.5px] hover:underline-offset-4"
            }
        >
            {children}
        </button>
    );
}
