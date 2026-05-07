import { Browser } from "@wailsio/runtime";
import { Update as UpdateSvc } from "@bindings/services";
import netbirdAppIcon from "@/assets/logos/netbird-app-icon.svg";
import pkg from "../../../package.json";
import { useStatus } from "@/hooks/useStatus";
import { Button } from "@/components/Button";

const LEGAL_LINKS: { label: string; url: string }[] = [
    { label: "Imprint", url: "https://netbird.io/imprint" },
    { label: "Privacy", url: "https://netbird.io/privacy" },
    { label: "CLA", url: "https://netbird.io/cla" },
    { label: "Terms of Service", url: "https://netbird.io/terms" },
];

function openUrl(url: string) {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
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

    return (
        <div className={"flex flex-col gap-5 max-w-2xl"}>
            <div className={"flex gap-6 items-center"}>
                <img
                    src={netbirdAppIcon}
                    alt={"NetBird"}
                    className={
                        "w-24 h-24 rounded-2xl shrink-0 border border-nb-gray-800"
                    }
                />
                <div className={"flex-1 min-w-0 flex flex-col gap-2"}>
                    <h2 className={"text-2xl font-semibold"}>NetBird</h2>
                    <div className={"text-sm text-nb-gray-300 space-y-0.5"}>
                        <div>GUI v{guiVersion}</div>
                        <div>Client v{daemonVersion}</div>
                    </div>
                </div>
            </div>

            {updateVersion && (
                <div
                    className={
                        "flex items-center justify-between gap-4 rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-3"
                    }
                >
                    <div>
                        <p className={"text-sm font-medium"}>
                            Version {updateVersion} is available.
                        </p>
                        <button
                            type={"button"}
                            onClick={() =>
                                openUrl(
                                    `https://github.com/netbirdio/netbird/releases/tag/v${updateVersion}`,
                                )
                            }
                            className={"text-xs text-netbird hover:underline"}
                        >
                            What's new?
                        </button>
                    </div>
                    <Button
                        variant={"primary"}
                        size={"sm"}
                        onClick={triggerUpdate}
                    >
                        Restart now
                    </Button>
                </div>
            )}

            <p className={"text-xs text-nb-gray-500"}>
                © {new Date().getFullYear()} NetBird. All Rights Reserved.
            </p>
            <div
                className={
                    "flex flex-wrap gap-x-3 gap-y-1 text-xs text-nb-gray-400"
                }
            >
                {LEGAL_LINKS.map((link, i) => (
                    <span key={link.url} className={"flex items-center"}>
                        {i > 0 && (
                            <span
                                className={"mr-3 text-nb-gray-700"}
                                aria-hidden
                            >
                                ·
                            </span>
                        )}
                        <button
                            type={"button"}
                            onClick={() => openUrl(link.url)}
                            className={"hover:text-nb-gray-200 transition"}
                        >
                            {link.label}
                        </button>
                    </span>
                ))}
            </div>
        </div>
    );
}
