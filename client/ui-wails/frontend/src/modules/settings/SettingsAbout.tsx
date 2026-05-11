import { Browser } from "@wailsio/runtime";
import { Update as UpdateSvc } from "@bindings/services";
import netbirdFull from "@/assets/logos/netbird-full.svg";
import pkg from "../../../package.json";
import { useStatus } from "@/hooks/useStatus";
import { Button } from "@/components/Button";
import { useAccentTrigger } from "@/modules/settings/SettingsAccent";

const LEGAL_LINKS: { label: string; url: string }[] = [
    { label: "Imprint", url: "https://netbird.io/imprint" },
    { label: "Privacy", url: "https://netbird.io/privacy" },
    { label: "CLA", url: "https://netbird.io/cla" },
    { label: "Terms of Service", url: "https://netbird.io/terms" },
];

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
}

function formatLastChecked(date: Date) {
    return date.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
}

export function SettingsAbout() {
    const { status } = useStatus();
    const guiVersion = pkg.version;
    const daemonVersion = status?.daemonVersion ?? "—";

    const updateVersion = (status?.events ?? [])
        .map((e) => e.metadata?.["new_version_available"])
        .find((v): v is string => Boolean(v));

    const triggerUpdate = () => {
        UpdateSvc.Trigger().catch(() => {});
    };

    const handleVersionClick = useAccentTrigger();

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
                    NetBird Client v{daemonVersion}
                </p>
                <p className={"text-sm text-nb-gray-300"}>GUI v{guiVersion}</p>
            </div>

            {updateVersion ? (
                <div
                    className={
                        "w-full max-w-md flex items-center justify-between gap-4 rounded-md border border-nb-gray-800 bg-nb-gray-910 px-4 py-3"
                    }
                >
                    <div>
                        <p className={"text-sm font-semibold"}>
                            Version {updateVersion} is available.
                        </p>
                        <button
                            type={"button"}
                            onClick={() =>
                                openUrl(
                                    `https://github.com/netbirdio/netbird/releases/tag/v${updateVersion}`,
                                )
                            }
                            className={
                                "text-sm text-netbird hover:underline hover:underline-offset-4 hover:decoration-[0.5px] font-medium"
                            }
                        >
                            What's new?
                        </button>
                    </div>
                    <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                        Restart Now
                    </Button>
                </div>
            ) : (
                <div className={"flex flex-col items-center gap-2"}>
                    <p className={"text-xs text-nb-gray-400 text-center"}>
                        Last checked for updates on {formatLastChecked(new Date())}
                    </p>
                    <Button variant={"secondary"} size={"sm"} onClick={triggerUpdate}>
                        Check for updates
                    </Button>
                </div>
            )}

            <p className={"text-sm text-nb-gray-300 text-center"}>
                © {new Date().getFullYear()} NetBird. All Rights Reserved.
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
