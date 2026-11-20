import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import Skeleton from "react-loading-skeleton";
import { AgentNetwork as AgentNetworkSvc } from "@bindings/services";
import type { AgentNetworkHarness } from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { Tooltip } from "@/components/Tooltip";
import { HelpText } from "@/components/typography/HelpText";
import { formatErrorMessage } from "@/lib/errors";
import { HarnessIcon } from "./HarnessIcon";
import { HarnessSetupDialog } from "./HarnessSetupDialog";

// Settings a disconnect left in place because the user changed them after setup.
type Kept = { harness: string; keys: string[] };

// Lists the coding agents NetBird can point at Agent Networks. The setup engine
// runs in the UI process, so it edits this user's own config files.
type SectionProps = {
    // Changes whenever the daemon reports new info, so provider lists refresh.
    refreshKey: number;
};

const LIST_CLASS =
    "overflow-hidden rounded-xl border border-nb-gray-800 bg-nb-gray-930/60 dark:border-nb-gray-900";
const ROW_CLASS = "flex items-center gap-4 border-b border-nb-gray-910 px-4 py-2.5 last:border-b-0";
const ROW_BUTTON_CLASS = "h-8 py-0";

export const HarnessSection = ({ refreshKey }: SectionProps) => {
    const { t } = useTranslation();
    const [harnesses, setHarnesses] = useState<AgentNetworkHarness[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [editing, setEditing] = useState<AgentNetworkHarness | null>(null);
    const [undoing, setUndoing] = useState<string | null>(null);
    const [kept, setKept] = useState<Kept | null>(null);

    const load = useCallback(async () => {
        try {
            setHarnesses(await AgentNetworkSvc.Harnesses());
            setError(null);
        } catch (e: unknown) {
            setError(formatErrorMessage(e));
        }
    }, []);

    useEffect(() => {
        void load();
    }, [load, refreshKey]);

    const undo = async (h: AgentNetworkHarness) => {
        setUndoing(h.id);
        setKept(null);
        try {
            const plan = await AgentNetworkSvc.UndoHarness(h.id);
            const keys = plan.changes.filter((c) => c.action === "keep").map((c) => c.key);
            if (keys.length > 0) setKept({ harness: h.id, keys });
        } catch (e: unknown) {
            setError(formatErrorMessage(e));
        } finally {
            setUndoing(null);
            void load();
        }
    };

    return (
        <section
            aria-labelledby={"an-harness-heading"}
            className={"border-t border-nb-gray-910 px-6 pt-6 pb-6"}
        >
            <h2
                id={"an-harness-heading"}
                className={"mb-2 text-xs font-semibold tracking-wider text-nb-gray-400 uppercase"}
            >
                {t("agentNetwork.harness.title")}
            </h2>
            <HelpText className={"mb-3"}>{t("agentNetwork.harness.description")}</HelpText>
            {error && (
                <div
                    role={"alert"}
                    className={
                        "mb-3 flex items-center gap-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-700 dark:text-red-300"
                    }
                >
                    <div className={"min-w-0 flex-1"}>
                        {!harnesses && <p>{t("agentNetwork.harness.loadError")}</p>}
                        <p className={"break-words select-text"}>{error}</p>
                    </div>
                    {!harnesses && (
                        <Button
                            variant={"secondary"}
                            size={"xs"}
                            className={ROW_BUTTON_CLASS}
                            onClick={() => void load()}
                        >
                            {t("agentNetwork.error.retry")}
                        </Button>
                    )}
                </div>
            )}
            {!harnesses && !error && <ListSkeleton />}
            {harnesses && (
                <ul className={LIST_CLASS}>
                    {harnesses.map((h) => (
                        <HarnessRow
                            key={h.id}
                            harness={h}
                            undoing={undoing === h.id}
                            kept={kept?.harness === h.id ? kept.keys : null}
                            onConfigure={() => {
                                setKept(null);
                                setEditing(h);
                            }}
                            onUndo={() => void undo(h)}
                        />
                    ))}
                </ul>
            )}
            <HarnessSetupDialog
                harness={editing}
                onOpenChange={(open) => !open && setEditing(null)}
                onApplied={() => {
                    setEditing(null);
                    void load();
                }}
            />
        </section>
    );
};

const ListSkeleton = () => {
    const { t } = useTranslation();
    return (
        <ul aria-busy={"true"} aria-label={t("common.loading")} className={LIST_CLASS}>
            {[0, 1, 2].map((i) => (
                <li key={i} className={ROW_CLASS}>
                    <div className={"flex-1"}>
                        <Skeleton width={110} height={14} />
                    </div>
                    <Skeleton width={64} height={30} />
                </li>
            ))}
        </ul>
    );
};

type RowProps = {
    harness: AgentNetworkHarness;
    undoing: boolean;
    kept: string[] | null;
    onConfigure: () => void;
    onUndo: () => void;
};

const HarnessRow = ({ harness, undoing, kept, onConfigure, onUndo }: RowProps) => {
    const { t } = useTranslation();
    const configured = harness.status !== "not_configured";
    const usable = harness.providers.length > 0;

    const configure = (
        <Button
            variant={"secondary"}
            size={"xs"}
            className={ROW_BUTTON_CLASS}
            disabled={!usable || undoing}
            onClick={onConfigure}
        >
            {configured
                ? t("agentNetwork.harness.reconfigure")
                : t("agentNetwork.harness.configure")}
        </Button>
    );

    return (
        <li aria-label={harness.name} className={ROW_CLASS}>
            <div className={"flex min-w-0 flex-1 flex-col gap-1"}>
                <div className={"flex min-w-0 items-center gap-2"}>
                    <HarnessIcon harness={harness.id} className={"shrink-0 text-nb-gray-200"} />
                    <h3 className={"truncate text-sm font-medium text-nb-gray-100"}>
                        {harness.name}
                    </h3>
                    <StatusBadge status={harness.status} />
                </div>
                {kept && (
                    <p role={"status"} className={"text-xs break-words text-nb-gray-300"}>
                        {t("agentNetwork.harness.kept", { keys: kept.join(", ") })}
                    </p>
                )}
            </div>
            <div className={"flex shrink-0 items-center gap-1.5"}>
                {configured && (
                    <Button
                        variant={"ghost"}
                        size={"xs"}
                        className={`${ROW_BUTTON_CLASS} px-2.5 text-nb-gray-300 shadow-none`}
                        loading={undoing}
                        onClick={onUndo}
                    >
                        {t("agentNetwork.harness.undo")}
                    </Button>
                )}
                {usable ? (
                    configure
                ) : (
                    <Tooltip
                        content={
                            <span className={"block max-w-[260px] leading-snug"}>
                                {t("agentNetwork.harness.noProvider")}
                            </span>
                        }
                        side={"left"}
                    >
                        <span className={"block"}>{configure}</span>
                    </Tooltip>
                )}
            </div>
        </li>
    );
};

// Only the states worth a second look get a badge; "not connected" is the default.
const StatusBadge = ({ status }: { status: string }) => {
    const { t } = useTranslation();
    switch (status) {
        case "configured":
            return <Badge variant={"success"}>{t("agentNetwork.harness.status.configured")}</Badge>;
        case "edited":
            return <Badge variant={"warning"}>{t("agentNetwork.harness.status.edited")}</Badge>;
        default:
            return null;
    }
};
