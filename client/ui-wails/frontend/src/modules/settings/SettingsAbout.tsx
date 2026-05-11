import { Browser } from "@wailsio/runtime";
import netbirdFull from "@/assets/logos/netbird-full.svg";
import pkg from "../../../package.json";
import { useStatus } from "@/hooks/useStatus";
import { NetBirdVersionCard } from "@/components/NetBirdVersionCard";
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

export function SettingsAbout() {
    const { status } = useStatus();
    const guiVersion = pkg.version;
    const daemonVersion = status?.daemonVersion ?? "—";

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

            <NetBirdVersionCard />

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
