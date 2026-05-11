import { ReactNode } from "react";
import { Browser } from "@wailsio/runtime";
import { Update as UpdateSvc } from "@bindings/services";
import { Button } from "@/components/Button";
import { useStatus } from "@/hooks/useStatus";
import { cn } from "@/lib/cn";

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
}

function formatLastChecked(date: Date) {
    return date.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function triggerUpdate() {
    UpdateSvc.Trigger().catch(() => {});
}

export function NetBirdVersionCard() {
    const { status } = useStatus();
    const updateVersion = (status?.events ?? [])
        .map((e) => e.metadata?.["new_version_available"])
        .find((v): v is string => Boolean(v));

    if (updateVersion) {
        return (
            <Card>
                <div>
                    <Title>Version {updateVersion} is available.</Title>
                    <Link
                        url={`https://github.com/netbirdio/netbird/releases/tag/v${updateVersion}`}
                    >
                        What's new?
                    </Link>
                </div>
                <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                    Restart Now
                </Button>
            </Card>
        );
    }

    return (
        <Card className={"max-w-md"}>
            <div>
                <Title>Last checked on {formatLastChecked(new Date())}</Title>
                <Link url={"https://github.com/netbirdio/netbird/releases/latest"}>Changelog</Link>
            </div>
            <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                Check for updates
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
