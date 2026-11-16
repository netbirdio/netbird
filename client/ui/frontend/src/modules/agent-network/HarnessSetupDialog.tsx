import { type FormEvent, useEffect, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import Skeleton from "react-loading-skeleton";
import { AgentNetwork as AgentNetworkSvc } from "@bindings/services";
import {
    HarnessSetup,
    type AgentNetworkHarness,
    type HarnessChange,
    type HarnessPlan,
} from "@bindings/services/models.js";
import * as Dialog from "@/components/dialog/Dialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { Input } from "@/components/inputs/Input";
import { Select } from "@/components/inputs/Select";
import { TruncatedText } from "@/components/TruncatedText";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { formatErrorMessage } from "@/lib/errors";

const PLAN_DEBOUNCE_MS = 300;

type Props = {
    harness: AgentNetworkHarness | null;
    onOpenChange: (open: boolean) => void;
    onApplied: (plan: HarnessPlan) => void;
};

export const HarnessSetupDialog = ({ harness, onOpenChange, onApplied }: Props) => {
    const { t } = useTranslation();
    return (
        <Dialog.Root open={harness !== null} onOpenChange={onOpenChange}>
            {harness && (
                <Dialog.Content
                    maxWidthClass={"max-w-lg"}
                    showClose={false}
                    srTitle={t("agentNetwork.harness.dialogTitle", { name: harness.name })}
                >
                    <SetupForm
                        key={harness.id}
                        harness={harness}
                        onCancel={() => onOpenChange(false)}
                        onApplied={onApplied}
                    />
                </Dialog.Content>
            )}
        </Dialog.Root>
    );
};

type FormProps = {
    harness: AgentNetworkHarness;
    onCancel: () => void;
    onApplied: (plan: HarnessPlan) => void;
};

// The preview the dialog shows, tagged with the request it answers so a plan
// for earlier picks is never shown or confirmed.
type PlanState = { key: string; plan: HarnessPlan | null; error: string | null };

const SetupForm = ({ harness, onCancel, onApplied }: FormProps) => {
    const { t } = useTranslation();
    const modelId = useId();
    const projectId = useId();
    const modelsId = useId();
    const [providerId, setProviderId] = useState(harness.providers[0]?.id ?? "");
    const provider = harness.providers.find((p) => p.id === providerId) ?? harness.providers[0];
    const [model, setModel] = useState(provider?.defaultModel ?? "");
    const [vertexProject, setVertexProject] = useState("");
    const [planState, setPlanState] = useState<PlanState | null>(null);
    const [applying, setApplying] = useState(false);
    const [applyError, setApplyError] = useState<string | null>(null);

    const req = new HarnessSetup({
        harness: harness.id,
        provider: provider?.id ?? "",
        model: model.trim(),
        vertexProject: vertexProject.trim(),
    });
    const reqKey = JSON.stringify(req);
    const needsProject = !!provider?.needsVertexProject && req.vertexProject === "";

    useEffect(() => {
        if (needsProject) return;
        let cancelled = false;
        const timer = setTimeout(() => {
            AgentNetworkSvc.PlanHarness(HarnessSetup.createFrom(reqKey))
                .then((plan) => !cancelled && setPlanState({ key: reqKey, plan, error: null }))
                .catch(
                    (e: unknown) =>
                        !cancelled &&
                        setPlanState({ key: reqKey, plan: null, error: formatErrorMessage(e) }),
                );
        }, PLAN_DEBOUNCE_MS);
        return () => {
            cancelled = true;
            clearTimeout(timer);
        };
    }, [reqKey, needsProject]);

    const current = planState?.key === reqKey ? planState : null;
    const plan = current?.plan ?? null;
    const canApply = !!plan && !plan.unparseable && plan.changes.length > 0 && !applying;

    const apply = async (e: FormEvent) => {
        e.preventDefault();
        if (!plan || !canApply) return;
        setApplying(true);
        setApplyError(null);
        try {
            // The user saw the conflicting keys in the preview; confirming replaces them.
            onApplied(await AgentNetworkSvc.ApplyHarness(req, plan.conflict));
        } catch (e: unknown) {
            setApplyError(formatErrorMessage(e));
        } finally {
            setApplying(false);
        }
    };

    if (!provider) return null;

    const restricted = !provider.allModelsAllowed && provider.models.length > 0;

    return (
        <form onSubmit={(e) => void apply(e)}>
            <div className={"flex flex-col gap-6 px-7"}>
                <div>
                    <Dialog.Title>
                        {t("agentNetwork.harness.dialogTitle", { name: harness.name })}
                    </Dialog.Title>
                    <Dialog.Description>
                        {harness.id === "claude-code"
                            ? t("agentNetwork.harness.dialogDescription.claudeCode")
                            : t("agentNetwork.harness.dialogDescription.generic", {
                                  name: harness.name,
                              })}
                    </Dialog.Description>
                </div>

                <div className={"grid grid-cols-2 gap-3"}>
                    <div className={"flex flex-col gap-2"}>
                        <Label as={"div"} className={"mb-0.5 ps-1"}>
                            {t("agentNetwork.harness.provider")}
                        </Label>
                        <Select
                            value={provider.id}
                            ariaLabel={t("agentNetwork.harness.provider")}
                            options={harness.providers.map((p) => ({ value: p.id, label: p.name }))}
                            onChange={(id) => {
                                setProviderId(id);
                                const next = harness.providers.find((p) => p.id === id);
                                setModel(next?.defaultModel ?? "");
                            }}
                        />
                    </div>
                    <div className={"flex flex-col gap-2"}>
                        {restricted ? (
                            <>
                                <Label as={"div"} className={"mb-0.5 ps-1"}>
                                    {t("agentNetwork.harness.model")}
                                </Label>
                                <Select
                                    value={model}
                                    ariaLabel={t("agentNetwork.harness.model")}
                                    options={provider.models.map((m) => ({ value: m, label: m }))}
                                    onChange={setModel}
                                />
                            </>
                        ) : (
                            <>
                                <Label htmlFor={modelId} className={"mb-0.5 ps-1"}>
                                    {t("agentNetwork.harness.model")}
                                </Label>
                                <Input
                                    id={modelId}
                                    dir={"ltr"}
                                    list={modelsId}
                                    value={model}
                                    placeholder={t("agentNetwork.harness.modelAuto", {
                                        name: harness.name,
                                    })}
                                    onChange={(e) => setModel(e.target.value)}
                                    spellCheck={false}
                                    autoComplete={"off"}
                                />
                                <datalist id={modelsId}>
                                    {provider.models.map((m) => (
                                        <option key={m} value={m} />
                                    ))}
                                </datalist>
                            </>
                        )}
                    </div>
                </div>

                {provider.needsVertexProject && (
                    <div className={"flex flex-col gap-2"}>
                        <div className={"ps-1"}>
                            <Label htmlFor={projectId} className={"mb-0.5"}>
                                {t("agentNetwork.harness.vertexProject")}
                            </Label>
                            <HelpText margin={false}>
                                {t("agentNetwork.harness.vertexProjectHelp")}
                            </HelpText>
                        </div>
                        <Input
                            id={projectId}
                            dir={"ltr"}
                            value={vertexProject}
                            onChange={(e) => setVertexProject(e.target.value)}
                            spellCheck={false}
                            autoComplete={"off"}
                        />
                    </div>
                )}

                <Preview
                    plan={plan}
                    error={current?.error ?? null}
                    pending={!current && !needsProject}
                />

                {applyError && (
                    <p role={"alert"} className={"text-xs text-red-500"}>
                        {applyError}
                    </p>
                )}

                <DialogActions className={"flex-row items-center justify-end gap-2.5 pt-2"}>
                    <Button type={"button"} variant={"secondary"} size={"sm"} onClick={onCancel}>
                        {t("common.cancel")}
                    </Button>
                    <Button
                        type={"submit"}
                        variant={"primary"}
                        size={"sm"}
                        disabled={!canApply}
                        loading={applying}
                    >
                        {plan?.conflict
                            ? t("agentNetwork.harness.replaceAndApply")
                            : t("agentNetwork.harness.apply")}
                    </Button>
                </DialogActions>
            </div>
        </form>
    );
};

const Preview = ({
    plan,
    error,
    pending,
}: {
    plan: HarnessPlan | null;
    error: string | null;
    pending: boolean;
}) => {
    const { t } = useTranslation();
    if (error) {
        return (
            <p role={"alert"} className={"text-xs text-red-500"}>
                {error}
            </p>
        );
    }
    if (!plan) {
        return pending ? (
            <div
                aria-busy={"true"}
                aria-label={t("agentNetwork.harness.planning")}
                className={PREVIEW_BOX_CLASS + " px-3 py-2"}
            >
                <Skeleton width={220} height={10} />
                <Skeleton count={3} height={12} />
            </div>
        ) : null;
    }
    if (plan.unparseable) {
        return (
            <div className={"flex flex-col gap-2"}>
                <p role={"status"} className={WARNING_CLASS}>
                    {t("agentNetwork.harness.unparseable", { file: plan.unparseable })}
                </p>
                {plan.snippets.map((s) => (
                    <div key={s.file} className={"flex flex-col gap-1"}>
                        <div className={"flex items-center gap-2"}>
                            <TruncatedText
                                text={s.file}
                                dir={"ltr"}
                                className={
                                    "min-w-0 flex-1 truncate font-mono text-xs text-nb-gray-300"
                                }
                            />
                            <Button variant={"secondary"} size={"xs"} copy={s.content}>
                                {t("common.copy")}
                            </Button>
                        </div>
                        <pre
                            dir={"ltr"}
                            className={
                                "max-h-48 overflow-auto rounded-md bg-nb-gray-930 p-3 font-mono text-xs text-nb-gray-200 select-text"
                            }
                        >
                            {s.content}
                        </pre>
                    </div>
                ))}
            </div>
        );
    }
    if (plan.changes.length === 0) {
        return (
            <p className={"text-xs text-nb-gray-300"}>{t("agentNetwork.harness.alreadySetUp")}</p>
        );
    }

    const files = [...new Set(plan.changes.map((c) => c.file))];
    return (
        <div className={"flex flex-col gap-2"}>
            <div className={PREVIEW_BOX_CLASS + " max-h-64 overflow-auto"}>
                {files.map((file) => (
                    <div key={file} className={"border-t border-nb-gray-910 first:border-t-0"}>
                        <TruncatedText
                            text={file}
                            dir={"ltr"}
                            className={
                                "block truncate px-3 pt-2 font-mono text-xs text-nb-gray-400"
                            }
                        />
                        <ul className={"px-3 pb-2"}>
                            {plan.changes
                                .filter((c) => c.file === file)
                                .map((c) => (
                                    <ChangeRow key={c.key} change={c} />
                                ))}
                        </ul>
                    </div>
                ))}
            </div>
            {plan.conflict && (
                <p role={"status"} className={WARNING_CLASS}>
                    {t("agentNetwork.harness.conflict")}
                </p>
            )}
        </div>
    );
};

const ChangeRow = ({ change }: { change: HarnessChange }) => {
    const { t } = useTranslation();
    const value = (v: string) => (v === "" ? t("agentNetwork.harness.absent") : v);
    return (
        <li className={"py-1 text-xs"}>
            <div className={"flex items-center gap-2"}>
                <TruncatedText
                    text={change.key}
                    dir={"ltr"}
                    className={"min-w-0 truncate font-mono text-nb-gray-100"}
                />
                {change.conflict && (
                    <Badge variant={"warning"}>{t("agentNetwork.harness.notOurs")}</Badge>
                )}
                {change.action !== "set" && (
                    <Badge variant={"neutral"}>
                        {change.action === "restore"
                            ? t("agentNetwork.harness.action.restore")
                            : t("agentNetwork.harness.action.keep")}
                    </Badge>
                )}
            </div>
            <div
                className={"mt-0.5 flex min-w-0 gap-1.5 font-mono text-xs text-nb-gray-400"}
                dir={"ltr"}
            >
                {/* The old value gives way first, so the new one stays readable. */}
                <TruncatedText
                    text={value(change.before)}
                    dir={"ltr"}
                    className={"min-w-0 truncate"}
                />
                {change.action !== "keep" && (
                    <>
                        <span aria-hidden={"true"}>→</span>
                        <TruncatedText
                            text={value(change.after)}
                            dir={"ltr"}
                            className={"max-w-[calc(100%-6rem)] shrink-0 truncate text-nb-gray-200"}
                        />
                    </>
                )}
            </div>
        </li>
    );
};

const PREVIEW_BOX_CLASS = "rounded-md border border-nb-gray-900 bg-nb-gray-930";
// The app's inline warning line, as under an Input.
const WARNING_CLASS = "text-xs text-orange-400";
