import { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Browser } from "@wailsio/runtime";
import { Button } from "@/components/Button";
import { useClientVersion } from "@/modules/auto-update/ClientVersionContext";
import { cn } from "@/lib/cn";

const GITHUB_RELEASES = "https://github.com/netbirdio/netbird/releases/latest";

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
}

function formatLastChecked(date: Date, locale?: string) {
    return date.toLocaleString(locale, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
}

export function UpdateVersionCard() {
    const { t, i18n } = useTranslation();
    const { updateVersion, enforced, triggerUpdate } = useClientVersion();

    if (updateVersion) {
        const titleKey = enforced
            ? "update.card.versionAvailableInstall"
            : "update.card.versionAvailableDownload";
        return (
            <Card>
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
                ) : (
                    <Button
                        variant={"primary"}
                        size={"xs"}
                        onClick={() => openUrl(GITHUB_RELEASES)}
                    >
                        {t("update.card.getInstaller")}
                    </Button>
                )}
            </Card>
        );
    }

    return (
        <Card className={"max-w-md"}>
            <div>
                <Title>
                    {t("update.card.lastChecked", {
                        date: formatLastChecked(new Date(), i18n.language),
                    })}
                </Title>
                <Link url={GITHUB_RELEASES}>{t("update.card.changelog")}</Link>
            </div>
            <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                {t("update.card.checkForUpdates")}
            </Button>
        </Card>
    );
}

function Card({ children, className }: { children: ReactNode; className?: string }) {
    return (
        <div
            className={cn(
                "w-full max-w-md flex items-center justify-between gap-4 rounded-md border border-nb-gray-800 bg-nb-gray-910 px-4 py-3",
                className,
            )}
        >
            {children}
        </div>
    );
}

function Title({ children }: { children: ReactNode }) {
    return <p className={"text-sm font-semibold"}>{children}</p>;
}

function Link({ url, children }: { url: string; children: ReactNode }) {
    return (
        <button
            type={"button"}
            onClick={() => openUrl(url)}
            className={
                "text-sm text-netbird hover:underline hover:underline-offset-4 hover:decoration-[0.5px] font-medium"
            }
        >
            {children}
        </button>
    );
}
