import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AgentNetwork as AgentNetworkSvc } from "@bindings/services";
import type { AgentNetworkHarness, HarnessPlan } from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { formatErrorMessage } from "@/lib/errors";
import { HarnessSetupDialog } from "./HarnessSetupDialog";

type Outcome = { harness: string; kind: "applied" | "undone"; plan: HarnessPlan };

// Lists the coding agents NetBird can point at Agent Networks. The setup engine
// runs in the UI process, so it edits this user's own config files.
type SectionProps = {
    // Changes whenever the daemon reports new info, so provider lists refresh.
    refreshKey: string;
    loginExpired: boolean;
};

export const HarnessSection = ({ refreshKey, loginExpired }: SectionProps) => {
    const { t } = useTranslation();
    const [harnesses, setHarnesses] = useState<AgentNetworkHarness[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [editing, setEditing] = useState<AgentNetworkHarness | null>(null);
    const [undoing, setUndoing] = useState<string | null>(null);
    const [outcome, setOutcome] = useState<Outcome | null>(null);

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
        setOutcome(null);
        try {
            const plan = await AgentNetworkSvc.UndoHarness(h.id);
            setOutcome({ harness: h.id, kind: "undone", plan });
        } catch (e: unknown) {
            setError(formatErrorMessage(e));
        } finally {
            setUndoing(null);
            void load();
        }
    };

    if (!harnesses) {
        return error ? <p className={"text-xs text-red-500"}>{error}</p> : null;
    }

    return (
        <section aria-labelledby={"an-harness-heading"} className={"flex flex-col gap-3"}>
            <div>
                <h2 id={"an-harness-heading"} className={"text-sm font-medium text-nb-gray-100"}>
                    {t("agentNetwork.harness.title")}
                </h2>
                <p className={"mt-1 text-xs text-nb-gray-350"}>
                    {t("agentNetwork.harness.description")}
                </p>
            </div>
            {error && <p className={"text-xs text-red-500"}>{error}</p>}
            {harnesses.map((h) => (
                <HarnessCard
                    key={h.id}
                    harness={h}
                    undoing={undoing === h.id}
                    outcome={outcome?.harness === h.id ? outcome : null}
                    onConfigure={() => {
                        setOutcome(null);
                        setEditing(h);
                    }}
                    onUndo={() => void undo(h)}
                />
            ))}
            <HarnessSetupDialog
                harness={editing}
                loginExpired={loginExpired}
                onOpenChange={(open) => !open && setEditing(null)}
                onApplied={(plan) => {
                    if (editing) setOutcome({ harness: editing.id, kind: "applied", plan });
                    setEditing(null);
                    void load();
                }}
            />
        </section>
    );
};

type CardProps = {
    harness: AgentNetworkHarness;
    undoing: boolean;
    outcome: Outcome | null;
    onConfigure: () => void;
    onUndo: () => void;
};

const HarnessCard = ({ harness, undoing, outcome, onConfigure, onUndo }: CardProps) => {
    const { t } = useTranslation();
    const configured = harness.status !== "not_configured";
    const usable = harness.providers.length > 0;

    return (
        <section
            aria-label={harness.name}
            className={"rounded-lg border border-nb-gray-900 bg-nb-gray-920 px-4 py-3"}
        >
            <div className={"flex items-center gap-2"}>
                <h3 className={"truncate text-sm font-medium text-nb-gray-100"}>{harness.name}</h3>
                <StatusBadge status={harness.status} />
                <div className={"ms-auto flex shrink-0 gap-2"}>
                    {configured && (
                        <Button
                            variant={"secondary"}
                            size={"xs"}
                            loading={undoing}
                            onClick={onUndo}
                        >
                            {t("agentNetwork.harness.undo")}
                        </Button>
                    )}
                    <Button
                        variant={configured ? "secondary" : "primary"}
                        size={"xs"}
                        disabled={!usable || undoing}
                        onClick={onConfigure}
                    >
                        {configured
                            ? t("agentNetwork.harness.reconfigure")
                            : t("agentNetwork.harness.configure")}
                    </Button>
                </div>
            </div>
            <p className={"mt-1 text-[0.7rem] break-all text-nb-gray-400"} dir={"ltr"}>
                {harness.files.join(", ")}
            </p>
            {!usable && (
                <p className={"mt-1 text-xs text-nb-gray-350"}>
                    {t("agentNetwork.harness.noProvider")}
                </p>
            )}
            {outcome && <OutcomeNote outcome={outcome} />}
        </section>
    );
};

const StatusBadge = ({ status }: { status: string }) => {
    const { t } = useTranslation();
    switch (status) {
        case "configured":
            return <Badge variant={"success"}>{t("agentNetwork.harness.status.configured")}</Badge>;
        case "edited":
            return <Badge variant={"warning"}>{t("agentNetwork.harness.status.edited")}</Badge>;
        default:
            return (
                <Badge variant={"neutral"}>{t("agentNetwork.harness.status.notConfigured")}</Badge>
            );
    }
};

const OutcomeNote = ({ outcome }: { outcome: Outcome }) => {
    const { t } = useTranslation();
    const kept = outcome.plan.changes.filter((c) => c.action === "keep").map((c) => c.key);
    return (
        <div role={"status"} className={"mt-2 flex flex-col gap-1 text-xs text-nb-gray-300"}>
            <p>
                {outcome.kind === "applied"
                    ? t("agentNetwork.harness.applied")
                    : t("agentNetwork.harness.undone")}
            </p>
            {kept.length > 0 && <p>{t("agentNetwork.harness.kept", { keys: kept.join(", ") })}</p>}
            {outcome.plan.backups.map((b) => (
                <p key={b} className={"text-[0.7rem] break-all text-nb-gray-400"} dir={"ltr"}>
                    {t("agentNetwork.harness.backup", { path: b })}
                </p>
            ))}
        </div>
    );
};
