import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import Skeleton from "react-loading-skeleton";
import { BotIcon, CircleAlertIcon, RefreshCwIcon, ShieldBanIcon, UserXIcon } from "lucide-react";
import type {
    AgentNetworkInfo,
    AgentNetworkLimit,
    AgentNetworkProvider,
} from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { SquareIcon } from "@/components/SquareIcon";
import { Tooltip } from "@/components/Tooltip";
import { TruncatedText } from "@/components/TruncatedText";
import { contentTop, EmptyState } from "@/components/empty-state/EmptyState";
import { useDirection } from "@/hooks/useDirection";
import { AGENT_NETWORK_POLL_MS, useAgentNetworkInfo } from "./useAgentNetworkInfo";
import { HarnessSection } from "./HarnessSection";

export const AgentNetworkUsage = () => {
    const { info, error, loading, fetchCount, refresh } = useAgentNetworkInfo({
        enabled: true,
        pollMs: AGENT_NETWORK_POLL_MS,
    });
    return (
        <AgentNetworkUsageView
            info={info}
            error={error}
            loading={loading}
            onRefresh={refresh}
            setup={info && <HarnessSection refreshKey={fetchCount} />}
        />
    );
};

type ViewProps = {
    info: AgentNetworkInfo | null;
    error: string | null;
    loading?: boolean;
    onRefresh?: () => void;
    // Rendered under the providers, only in the "ok" state with providers.
    setup?: ReactNode;
};

// Pure view, kept apart from the fetching so every state can be rendered from a fixture.
export const AgentNetworkUsageView = ({
    info,
    error,
    loading = false,
    onRefresh,
    setup,
}: ViewProps) => {
    const { t } = useTranslation();
    const dir = useDirection();

    if (!info) {
        return error ? <LoadError error={error} onRetry={onRefresh} /> : <UsageSkeleton />;
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
            return (
                <EmptyState
                    icon={CircleAlertIcon}
                    title={t("agentNetwork.unknown.title")}
                    description={t("agentNetwork.unknown.description")}
                />
            );
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

    const now = new Date();

    return (
        <div className={"flex h-full min-h-0 w-full flex-col"}>
            <div
                className={
                    "flex h-12 shrink-0 items-center gap-2 border-b border-nb-gray-910 ps-6 pe-3"
                }
            >
                <h2 className={"text-xs font-semibold tracking-wider text-nb-gray-400 uppercase"}>
                    {t("agentNetwork.usage.title")}
                </h2>
                <span className={"flex-1"} />
                {onRefresh && <RefreshButton loading={loading} onRefresh={onRefresh} />}
            </div>
            <ScrollArea.Root dir={dir} type={"auto"} className={"min-h-0 flex-1 overflow-hidden"}>
                {/* Radix wraps the content in a display:table box, which grows with
                    nowrap text instead of letting it truncate. */}
                <ScrollArea.Viewport className={"h-full w-full [&>div]:block!"}>
                    {error && (
                        <div
                            role={"alert"}
                            className={
                                "mx-6 mt-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-700 dark:text-red-300"
                            }
                        >
                            {t("agentNetwork.error.stale")}
                            <span className={"block opacity-80 select-text"}>{error}</span>
                        </div>
                    )}
                    <div className={"flex flex-col divide-y divide-nb-gray-920"}>
                        {info.providers.map((p) => (
                            <ProviderSection key={p.id} provider={p} now={now} />
                        ))}
                    </div>
                    {setup}
                </ScrollArea.Viewport>
                <ScrollArea.Scrollbar
                    orientation={"vertical"}
                    className={
                        "flex w-1.5 touch-none bg-transparent py-1 transition-colors select-none"
                    }
                >
                    <ScrollArea.Thumb
                        className={
                            "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
                        }
                    />
                </ScrollArea.Scrollbar>
            </ScrollArea.Root>
        </div>
    );
};

const RefreshButton = ({ loading, onRefresh }: { loading: boolean; onRefresh: () => void }) => {
    const { t } = useTranslation();
    return (
        <Tooltip content={t("common.refresh")}>
            <button
                type={"button"}
                onClick={onRefresh}
                disabled={loading}
                aria-label={t("common.refresh")}
                aria-busy={loading}
                className={cn(
                    "flex h-8 w-8 shrink-0 items-center justify-center rounded-md",
                    "text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100",
                    "cursor-default outline-hidden transition-colors",
                    "focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                    "wails-no-draggable",
                    "disabled:opacity-50 disabled:hover:bg-transparent",
                )}
            >
                <RefreshCwIcon
                    size={14}
                    aria-hidden={"true"}
                    className={loading ? "animate-spin" : undefined}
                />
            </button>
        </Tooltip>
    );
};

const UsageSkeleton = () => {
    const { t } = useTranslation();
    return (
        <div aria-busy={"true"} aria-label={t("common.loading")} className={"px-6 py-4"}>
            <Skeleton width={90} height={14} className={"mb-5"} />
            {[0, 1].map((i) => (
                <div key={i} className={"mb-6"}>
                    <Skeleton width={140} height={14} />
                    <Skeleton height={8} className={"mt-3"} />
                    <Skeleton width={180} height={10} />
                </div>
            ))}
        </div>
    );
};

// EmptyState's layout plus a retry button, which the shared component has no slot for.
const LoadError = ({ error, onRetry }: { error: string; onRetry?: () => void }) => {
    const { t } = useTranslation();
    return (
        <div role={"alert"} className={"py-12 text-center"}>
            <div
                className={"relative mx-auto flex max-w-sm flex-col items-center justify-start"}
                style={{ top: contentTop("7.8rem") }}
            >
                <SquareIcon icon={CircleAlertIcon} className={"mb-3"} />
                <p className={"mb-1 text-[0.95rem] font-medium text-nb-gray-200"}>
                    {t("agentNetwork.error.title")}
                </p>
                <p className={"text-sm text-nb-gray-350"}>{t("agentNetwork.error.description")}</p>
                {onRetry && (
                    <Button variant={"secondary"} size={"xs"} className={"mt-4"} onClick={onRetry}>
                        {t("agentNetwork.error.retry")}
                    </Button>
                )}
                <p className={"mt-4 text-xs break-words text-nb-gray-400 select-text"}>{error}</p>
            </div>
        </div>
    );
};

const ProviderSection = ({ provider, now }: { provider: AgentNetworkProvider; now: Date }) => {
    const { t, i18n } = useTranslation();
    // The catalog id is only worth showing when the admin gave the provider another name.
    const showCatalogId =
        provider.catalogId !== "" &&
        provider.catalogId.toLowerCase() !== provider.name.toLowerCase();
    const reset = soonestReset(provider.limits);
    return (
        <section aria-label={provider.name} className={"min-w-0 px-6 py-4"}>
            <div className={"flex min-w-0 items-center gap-2"}>
                <h3 className={"min-w-0 text-sm font-medium text-nb-gray-100"}>
                    <TruncatedText text={provider.name} className={"block truncate"} />
                </h3>
                {showCatalogId && (
                    <span className={"shrink-0 text-xs text-nb-gray-400"}>
                        {provider.catalogId}
                    </span>
                )}
                <span className={"flex-1"} />
                {provider.exhausted && (
                    <Badge variant={"danger"}>{t("agentNetwork.badge.exhausted")}</Badge>
                )}
            </div>
            {provider.exhausted && (
                <p className={"mt-1 text-xs text-nb-gray-300"}>
                    {reset
                        ? t("agentNetwork.exhaustedUntil", {
                              relative: formatUntil(reset, now, i18n.language),
                          })
                        : t("agentNetwork.exhaustedDescription")}
                </p>
            )}
            {!provider.exhausted && (provider.unlimited || provider.limits.length === 0) && (
                <p className={"mt-1 text-xs text-nb-gray-400"}>{t("agentNetwork.noLimits")}</p>
            )}
            {provider.limits.length > 0 && (
                <div className={"mt-3 grid grid-cols-2"}>
                    {UNITS.map((unit, i) => (
                        <LimitHalf
                            key={unit}
                            unit={unit}
                            limit={tightest(provider.limits, unit)}
                            now={now}
                            className={i === 0 ? "pe-4" : "border-s border-nb-gray-910 ps-4"}
                        />
                    ))}
                </div>
            )}
        </section>
    );
};

const UNITS = ["tokens", "usd"] as const;
type Unit = (typeof UNITS)[number];

// Every cap of a unit binds, so the one closest to running out is the one that
// stops the user first. Ties go to the smaller cap.
const tightest = (limits: AgentNetworkLimit[], unit: Unit): AgentNetworkLimit | null => {
    const ratio = (l: AgentNetworkLimit) => (l.cap > 0 ? l.used / l.cap : 1);
    return (
        limits
            .filter((l) => l.unit === unit)
            .sort((a, b) => ratio(b) - ratio(a) || a.cap - a.used - (b.cap - b.used))[0] ?? null
    );
};

type HalfProps = { unit: Unit; limit: AgentNetworkLimit | null; now: Date; className?: string };

// One unit's allowance. A unit without a cap is unlimited and gets no bar.
const LimitHalf = ({ unit, limit, now, className }: HalfProps) => {
    const { t, i18n } = useTranslation();
    const lang = i18n.language;
    const label = t(unit === "usd" ? "agentNetwork.limit.spend" : "agentNetwork.limit.tokens");

    if (!limit) {
        return (
            <div className={cn("flex min-w-0 items-baseline gap-2 text-xs", className)}>
                <span className={"min-w-0 flex-1 truncate text-nb-gray-200"}>{label}</span>
                <span className={"shrink-0 text-nb-gray-400"}>
                    {t("agentNetwork.limit.unlimited")}
                </span>
            </div>
        );
    }

    const ratio = limit.cap > 0 ? Math.min(limit.used / limit.cap, 1) : 1;
    const percent = Math.round(ratio * 100);
    const exact = t(
        unit === "usd" ? "agentNetwork.limit.usedOfCapUsd" : "agentNetwork.limit.usedOfCapTokens",
        {
            used: formatAmount(unit, limit.used, lang, false),
            cap: formatAmount(unit, limit.cap, lang, false),
        },
    );
    const used = t("agentNetwork.limit.used", {
        used: formatAmount(unit, limit.used, lang, true),
    });
    const resets = limit.resetsAt ? new Date(limit.resetsAt) : null;

    return (
        <div className={cn("min-w-0 text-xs", className)}>
            <div className={"flex items-baseline gap-2"}>
                <span className={"min-w-0 flex-1 truncate text-nb-gray-200"}>{label}</span>
                <span className={"shrink-0 text-nb-gray-300 tabular-nums"}>
                    {formatAmount(unit, limit.cap, lang, true)}
                </span>
            </div>
            <div
                role={"progressbar"}
                aria-label={label}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={percent}
                aria-valuetext={exact}
                className={"mt-1.5 h-1.5 overflow-hidden rounded-full bg-nb-gray-900"}
            >
                <div
                    className={cn("h-full rounded-full transition-all", barColor(ratio))}
                    style={{ width: `${percent}%` }}
                />
            </div>
            <p className={"mt-1.5 truncate text-nb-gray-400 tabular-nums"}>
                {used}
                {resets && (
                    <>
                        {" · "}
                        <Tooltip content={formatUntil(resets, now, lang)}>
                            <span>
                                {t("agentNetwork.limit.resets", {
                                    when: formatReset(resets, now, lang),
                                })}
                            </span>
                        </Tooltip>
                    </>
                )}
            </p>
        </div>
    );
};

// Neutral until it needs attention, so the brand color stays reserved for actions.
const barColor = (ratio: number): string => {
    if (ratio >= 1) return "bg-red-500";
    if (ratio >= 0.8) return "bg-yellow-500";
    return "bg-nb-gray-500";
};

// The reset of the used-up limit that comes back first, which is when requests work again.
const soonestReset = (limits: AgentNetworkLimit[]): Date | null => {
    const times = limits
        .filter((l) => l.resetsAt && l.used >= l.cap)
        .map((l) => new Date(l.resetsAt).getTime());
    return times.length > 0 ? new Date(Math.min(...times)) : null;
};

const formatAmount = (unit: string, value: number, lang: string, compact: boolean): string => {
    if (unit === "usd") {
        return new Intl.NumberFormat(lang, { style: "currency", currency: "USD" }).format(value);
    }
    return new Intl.NumberFormat(
        lang,
        compact ? { notation: "compact", maximumFractionDigits: 1 } : { maximumFractionDigits: 0 },
    ).format(value);
};

// The clock time today, the weekday within a week, the date beyond, so nobody
// has to add hours to the current time.
const formatReset = (at: Date, now: Date, lang: string): string => {
    const days = (at.getTime() - now.getTime()) / 86_400_000;
    if (at.toDateString() === now.toDateString()) {
        return new Intl.DateTimeFormat(lang, { timeStyle: "short" }).format(at);
    }
    if (days < 7) {
        return new Intl.DateTimeFormat(lang, {
            weekday: "short",
            hour: "numeric",
            minute: "2-digit",
        }).format(at);
    }
    return new Intl.DateTimeFormat(lang, { day: "numeric", month: "short" }).format(at);
};

// Largest whole unit, localized by the platform ("in 42 minutes", "dans 3 jours").
const formatUntil = (at: Date, now: Date, lang: string): string => {
    const seconds = Math.max(0, (at.getTime() - now.getTime()) / 1000);
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
    if (seconds >= 86_400) return rtf.format(Math.floor(seconds / 86_400), "day");
    if (seconds >= 3_600) return rtf.format(Math.floor(seconds / 3_600), "hour");
    return rtf.format(Math.max(1, Math.floor(seconds / 60)), "minute");
};
