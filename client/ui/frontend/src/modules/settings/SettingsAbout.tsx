import type { ComponentType, SVGProps } from "react";
import { useTranslation } from "react-i18next";
import { Browser } from "@wailsio/runtime";
import { BookOpen, MessageSquareText, MessagesSquare } from "lucide-react";
import netbirdFull from "@/assets/logos/netbird-full.svg";
import netbirdFullLight from "@/assets/logos/netbird-full-light.svg";

// Brand glyphs from simpleicons.org (lucide deprecated its brand icons).
const GithubIcon = (props: SVGProps<SVGSVGElement>) => (
    <svg viewBox={"0 0 24 24"} fill={"currentColor"} {...props}>
        <path
            d={
                "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"
            }
        />
    </svg>
);
const DiscordIcon = (props: SVGProps<SVGSVGElement>) => (
    <svg viewBox={"0 0 24 24"} fill={"currentColor"} {...props}>
        <path
            d={
                "M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z"
            }
        />
    </svg>
);
import { useStatus } from "@/contexts/StatusContext.tsx";
import { useGuiVersion } from "@/hooks/useGuiVersion";
import { UpdateVersionCard } from "@/modules/auto-update/UpdateVersionCard";
import { useAccentTrigger } from "@/modules/settings/SettingsAccent";

function openUrl(url: string) {
    Browser.OpenURL(url).catch(() => {
        window.open(url, "_blank");
    });
}

export function SettingsAbout() {
    const { t } = useTranslation();
    const { status } = useStatus();
    const guiVersion = useGuiVersion();
    const daemonVersion = status?.daemonVersion ?? "—";

    const handleVersionClick = useAccentTrigger();

    const COMMUNITY_LINKS: {
        label: string;
        url: string;
        Icon: ComponentType<SVGProps<SVGSVGElement>>;
        iconClassName?: string;
    }[] = [
        {
            label: t("settings.about.community.github"),
            url: "https://github.com/netbirdio/netbird",
            Icon: GithubIcon,
            iconClassName: "h-3 w-3",
        },
        {
            label: t("settings.about.community.discord"),
            url: "https://docs.netbird.io/discord-url",
            Icon: DiscordIcon,
            iconClassName: "h-3 w-3",
        },
        {
            label: t("settings.about.community.forum"),
            url: "https://forum.netbird.io",
            Icon: MessagesSquare,
        },
        {
            label: t("settings.about.community.documentation"),
            url: "https://docs.netbird.io",
            Icon: BookOpen,
        },
        {
            label: t("settings.about.community.feedback"),
            url: "https://forms.gle/TeLw2zrXEdw6RcQ36",
            Icon: MessageSquareText,
        },
    ];

    const LEGAL_LINKS: { label: string; url: string }[] = [
        { label: t("settings.about.links.imprint"), url: "https://netbird.io/imprint" },
        { label: t("settings.about.links.privacy"), url: "https://netbird.io/privacy" },
        { label: t("settings.about.links.cla"), url: "https://netbird.io/cla" },
        { label: t("settings.about.links.terms"), url: "https://netbird.io/terms" },
    ];

    return (
        <div
            className={
                "mx-auto flex min-h-[calc(100vh-12rem)] max-w-2xl flex-col items-center justify-center gap-4"
            }
        >
            <img
                src={netbirdFullLight}
                alt={t("common.netbird")}
                className={"h-7 w-auto dark:hidden"}
            />
            <img
                src={netbirdFull}
                alt={t("common.netbird")}
                className={"hidden h-7 w-auto dark:block"}
            />
            <div className={"flex flex-col items-center gap-0.5 text-center"}>
                <button
                    type={"button"}
                    onClick={handleVersionClick}
                    className={
                        "cursor-text bg-transparent text-sm font-semibold text-nb-gray-100 outline-hidden select-text"
                    }
                >
                    {daemonVersion === "development" ? (
                        <span>
                            {t("settings.about.clientName")}{" "}
                            <span dir={"auto"} className={"font-mono text-yellow-400"}>
                                {t("settings.about.development")}
                            </span>
                        </span>
                    ) : (
                        t("settings.about.client", { version: daemonVersion })
                    )}
                </button>
                <p className={"cursor-text text-sm font-medium text-nb-gray-250 select-text"}>
                    {guiVersion === "development" ? (
                        <span>
                            {t("settings.about.guiName")}{" "}
                            <span dir={"auto"} className={"font-mono text-yellow-400"}>
                                {t("settings.about.development")}
                            </span>
                        </span>
                    ) : (
                        t("settings.about.gui", { version: guiVersion })
                    )}
                </p>
            </div>

            <UpdateVersionCard />

            <p className={"mt-2 text-center text-sm text-nb-gray-300"}>
                {t("settings.about.copyright", { year: new Date().getFullYear() })}
            </p>
            <div
                className={"flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs text-nb-gray-200"}
            >
                {COMMUNITY_LINKS.map(({ label, url, Icon, iconClassName }) => (
                    <button
                        key={url}
                        type={"button"}
                        tabIndex={0}
                        onClick={() => openUrl(url)}
                        className={
                            "inline-flex items-center gap-1.5 rounded-xs decoration-[0.5px] underline-offset-4 outline-hidden transition hover:text-nb-gray-100 hover:underline focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940"
                        }
                    >
                        <Icon aria-hidden={"true"} className={iconClassName ?? "h-3.5 w-3.5"} />
                        <span>{label}</span>
                    </button>
                ))}
            </div>
            <div
                className={"flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs text-nb-gray-200"}
            >
                {LEGAL_LINKS.map((link) => (
                    <button
                        key={link.url}
                        type={"button"}
                        tabIndex={0}
                        onClick={() => openUrl(link.url)}
                        className={
                            "rounded-xs decoration-[0.5px] underline-offset-4 outline-hidden transition hover:text-nb-gray-100 hover:underline focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940"
                        }
                    >
                        {link.label}
                    </button>
                ))}
            </div>
        </div>
    );
}
