import { ComponentType } from "react";
import { useTranslation } from "react-i18next";
import { Browser } from "@wailsio/runtime";
import { ExternalLinkIcon, LucideProps } from "lucide-react";
import { cn } from "@/lib/cn";
import { SquareIcon } from "./SquareIcon";

type Props = {
    icon: ComponentType<LucideProps>;
    title: string;
    description?: string;
    learnMoreUrl?: string;
    learnMoreTopic?: string;
    className?: string;
};

const openUrl = (url: string) => {
    void Browser.OpenURL(url).catch(() => window.open(url, "_blank"));
};

export const EmptyState = ({
    icon,
    title,
    description,
    learnMoreUrl,
    learnMoreTopic,
    className,
}: Props) => {
    const { t } = useTranslation();
    return (
        <div className={cn("py-12 text-center", className)}>
            <div
                className={
                    "flex flex-col items-center justify-center max-w-sm mx-auto"
                }
            >
                <SquareIcon icon={icon} className={"mb-3"} />
                <p className={"text-base font-semibold text-nb-gray-200 mb-1"}>
                    {title}
                </p>
                {description && (
                    <p className={"text-sm text-nb-gray-350"}>{description}</p>
                )}
                {learnMoreUrl && learnMoreTopic && (
                    <p className={"text-sm text-nb-gray-350"}>
                        {t("common.learnMoreAbout")}{" "}
                        <a
                            href={learnMoreUrl}
                            onClick={(e) => {
                                e.preventDefault();
                                openUrl(learnMoreUrl);
                            }}
                            className={cn(
                                "text-netbird hover:underline underline-offset-4",
                                "cursor-pointer wails-no-draggable",
                                "inline-flex items-center gap-1",
                            )}
                        >
                            {learnMoreTopic}
                            <ExternalLinkIcon
                                size={12}
                                className={"shrink-0"}
                            />
                        </a>
                    </p>
                )}
            </div>
        </div>
    );
};
