import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { BotIcon, CircleAlertIcon, ShieldBanIcon, UserXIcon } from "lucide-react";
import type {
    AgentNetworkInfo,
    AgentNetworkLimit,
    AgentNetworkProvider,
} from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/Badge";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { useDirection } from "@/hooks/useDirection";
import { AGENT_NETWORK_POLL_MS, useAgentNetworkInfo } from "./useAgentNetworkInfo";

export const AgentNetworkUsage = () => {
    const { info, error } = useAgentNetworkInfo({ enabled: true, pollMs: AGENT_NETWORK_POLL_MS });
    return <AgentNetworkUsageView info={info} error={error} />;
};

type ViewProps = {
    info: AgentNetworkInfo | null;
    error: string | null;
};

// Pure view, kept apart from the fetching so every state can be rendered from a fixture.
export const AgentNetworkUsageView = ({ info, error }: ViewProps) => {
    const { t } = useTranslation();
    const dir = useDirection();

    if (!info) {
        if (!error) return null;
        return (
            <EmptyState
                icon={CircleAlertIcon}
                title={t("agentNetwork.error.title")}
                description={error}
            />
        );
    }

    switch (info.state) {
        case "no_user":
            return (
                <EmptyState
                    icon={UserXIcon}
                    title={t("agentNetwork.noUser.title")}
                    description={t("agentNetwork.noUser.description")}
                />
            );
        case "user_blocked":
            return (
                <EmptyState
                    icon={ShieldBanIcon}
                    title={t("agentNetwork.blocked.title")}
                    description={t("agentNetwork.blocked.description")}
                />
            );
        case "ok":
            break;
        default:
            return null;
    }

    if (info.providers.length === 0) {
        return (
            <EmptyState
                icon={BotIcon}
                title={t("agentNetwork.noProviders.title")}
                description={t("agentNetwork.noProviders.description")}
            />
        );
    }

    const now = info.computedAt ? new Date(info.computedAt) : new Date();

    return (
        <ScrollArea.Root dir={dir} type={"auto"} className={"min-h-0 flex-1 overflow-hidden"}>
            <ScrollArea.Viewport className={"h-full w-full"}>
                <div className={"flex flex-col gap-3 px-6 py-4"}>
                    {info.loginExpired && (
                        <p
                            role={"alert"}
                            className={cn(
                                "rounded-md border px-3 py-2 text-xs",
                                "border-yellow-300 bg-yellow-100 text-yellow-800",
                                "dark:border-yellow-700 dark:bg-yellow-900 dark:text-yellow-200",
                            )}
                        >
                            {t("agentNetwork.loginExpired")}
                        </p>
                    )}
                    {error && (
                        <p className={"text-xs text-red-500"}>
                            {t("agentNetwork.error.stale", { error })}
                        </p>
                    )}
                    {info.userEmail && (
                        <p className={"text-xs text-nb-gray-350"}>
                            {t("agentNetwork.signedInAs", { email: info.userEmail })}
                        </p>
                    )}
                    {info.providers.map((p) => (
                        <ProviderCard key={p.id} provider={p} now={now} />
                    ))}
                </div>
            </ScrollArea.Viewport>
            <ScrollArea.Scrollbar
                orientation={"vertical"}
                className={
                    "flex w-1.5 touch-none bg-transparent py-1 transition-colors select-none"
                }
            >
                <ScrollArea.Thumb
                    className={"relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"}
                />
            </ScrollArea.Scrollbar>
        </ScrollArea.Root>
    );
};

const ProviderCard = ({ provider, now }: { provider: AgentNetworkProvider; now: Date }) => {
    const { t } = useTranslation();
    return (
        <section
            aria-label={provider.name}
            className={"rounded-lg border border-nb-gray-900 bg-nb-gray-920 px-4 py-3"}
        >
            <div className={"flex items-center gap-2"}>
                <h3 className={"truncate text-sm font-medium text-nb-gray-100"}>{provider.name}</h3>
                <span className={"truncate text-xs text-nb-gray-400"}>{provider.catalogId}</span>
                <span className={"flex-1"} />
                {provider.exhausted && (
                    <Badge variant={"danger"}>{t("agentNetwork.badge.exhausted")}</Badge>
                )}
                {!provider.exhausted && provider.unlimited && (
                    <Badge variant={"success"}>{t("agentNetwork.badge.unlimited")}</Badge>
                )}
            </div>
            {provider.exhausted && (
                <p className={"mt-1 text-xs text-red-500"}>
                    {t("agentNetwork.exhaustedDescription")}
                </p>
            )}
            {provider.limits.length === 0 && !provider.unlimited && (
                <p className={"mt-2 text-xs text-nb-gray-350"}>{t("agentNetwork.noLimits")}</p>
            )}
            <ul className={"mt-1 flex flex-col"}>
                {provider.limits.map((l, i) => (
                    <LimitRow
                        key={`${l.source}:${l.sourceId}:${l.unit}:${l.scope}:${i}`}
                        limit={l}
                        now={now}
                    />
                ))}
            </ul>
        </section>
    );
};

const LimitRow = ({ limit, now }: { limit: AgentNetworkLimit; now: Date }) => {
    const { t, i18n } = useTranslation();
    const lang = i18n.language;
    const ratio = limit.cap > 0 ? Math.min(limit.used / limit.cap, 1) : 1;
    const percent = Math.round(ratio * 100);

    const sourceLabel =
        limit.source === "account_rule"
            ? t("agentNetwork.limit.accountRule", { name: limit.sourceName || limit.sourceId })
            : t("agentNetwork.limit.policy", { name: limit.sourceName || limit.sourceId });
    const scopeLabel =
        limit.scope === "group"
            ? t("agentNetwork.limit.group", { name: limit.groupName || limit.groupId })
            : t("agentNetwork.limit.you");
    const usedOfCap = t(
        limit.unit === "usd"
            ? "agentNetwork.limit.usedOfCapUsd"
            : "agentNetwork.limit.usedOfCapTokens",
        {
            used: formatAmount(limit.unit, limit.used, lang),
            cap: formatAmount(limit.unit, limit.cap, lang),
        },
    );

    return (
        <li className={"border-t border-nb-gray-910 py-2.5 first:border-t-0"}>
            <div className={"flex items-baseline gap-2 text-xs"}>
                <span className={"min-w-0 flex-1 truncate text-nb-gray-200"}>
                    {sourceLabel} · {scopeLabel}
                </span>
                <span className={"shrink-0 text-nb-gray-300 tabular-nums"}>{usedOfCap}</span>
            </div>
            <div
                role={"progressbar"}
                aria-label={`${sourceLabel} · ${scopeLabel}`}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={percent}
                aria-valuetext={usedOfCap}
                className={"mt-1.5 h-1.5 overflow-hidden rounded-full bg-nb-gray-900"}
            >
                <div
                    className={cn(
                        "h-full rounded-full transition-all",
                        ratio >= 1 ? "bg-red-500" : ratio >= 0.8 ? "bg-yellow-500" : "bg-netbird",
                    )}
                    style={{ width: `${percent}%` }}
                />
            </div>
            {limit.resetsAt && (
                <p className={"mt-1 text-[0.7rem] text-nb-gray-400"}>
                    {t("agentNetwork.limit.resets", {
                        relative: formatUntil(new Date(limit.resetsAt), now, lang),
                        at: formatAt(new Date(limit.resetsAt), lang),
                    })}
                </p>
            )}
        </li>
    );
};

const formatAmount = (unit: string, value: number, lang: string): string =>
    unit === "usd"
        ? new Intl.NumberFormat(lang, { style: "currency", currency: "USD" }).format(value)
        : new Intl.NumberFormat(lang, { maximumFractionDigits: 0 }).format(value);

const formatAt = (at: Date, lang: string): string =>
    new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(at);

// Largest whole unit, localized by the platform ("in 42 minutes", "dans 3 jours").
const formatUntil = (at: Date, now: Date, lang: string): string => {
    const seconds = Math.max(0, (at.getTime() - now.getTime()) / 1000);
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
    if (seconds >= 86_400) return rtf.format(Math.floor(seconds / 86_400), "day");
    if (seconds >= 3_600) return rtf.format(Math.floor(seconds / 3_600), "hour");
    return rtf.format(Math.max(1, Math.floor(seconds / 60)), "minute");
};
