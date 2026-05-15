import type { ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";
import { FolderOpen } from "lucide-react";
import { Debug as DebugSvc } from "@bindings/services";
import type { DebugBundleResult } from "@bindings/services/models.js";
import { Button } from "@/components/Button";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import HelpText from "@/components/HelpText.tsx";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { StatusPanel } from "@/components/StatusPanel";
import { cn } from "@/lib/cn";
import type { DebugStage } from "@/modules/debug-bundle/useDebugBundle.ts";
import { useDebugBundleContext } from "@/modules/debug-bundle/useDebugBundleContext.ts";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";

export function SettingsTroubleshooting() {
    const { t } = useTranslation();
    const {
        anonymize,
        setAnonymize,
        systemInfo,
        setSystemInfo,
        upload,
        setUpload,
        trace,
        setTrace,
        traceMinutes,
        setTraceMinutes,
        run,
        stage,
        cancel,
        reset,
    } = useDebugBundleContext();

    if (stage.kind === "done") {
        return (
            <DoneResult
                result={stage.result}
                uploaded={stage.uploadAttempted}
                onClose={reset}
            />
        );
    }
    if (stage.kind !== "idle") {
        return <ProgressSection stage={stage} onCancel={cancel} />;
    }

    return (
        <SectionGroup title={t("settings.troubleshooting.section.title")}>
            <HelpText className={"-mt-2 mb-2"}>
                <Trans i18nKey={"settings.troubleshooting.intro"} components={{ br: <br /> }} />
            </HelpText>

            <FancyToggleSwitch
                value={anonymize}
                onChange={setAnonymize}
                label={t("settings.troubleshooting.anonymize.label")}
                helpText={t("settings.troubleshooting.anonymize.help")}
            />
            <FancyToggleSwitch
                value={systemInfo}
                onChange={setSystemInfo}
                label={t("settings.troubleshooting.systemInfo.label")}
                helpText={t("settings.troubleshooting.systemInfo.help")}
            />
            <FancyToggleSwitch
                value={upload}
                onChange={setUpload}
                label={t("settings.troubleshooting.upload.label")}
                helpText={t("settings.troubleshooting.upload.help")}
            />
            <FancyToggleSwitch
                value={trace}
                onChange={setTrace}
                label={t("settings.troubleshooting.trace.label")}
                helpText={t("settings.troubleshooting.trace.help")}
            />
            <div
                className={cn(
                    "flex items-center gap-6 justify-between",
                    !trace && "opacity-50 pointer-events-none",
                )}
            >
                <div className={"flex-1 max-w-md"}>
                    <Label as={"div"}>{t("settings.troubleshooting.duration.label")}</Label>
                    <HelpText margin={false}>
                        {t("settings.troubleshooting.duration.help")}
                    </HelpText>
                </div>
                <div className={"w-40 shrink-0"}>
                    <Input
                        type={"number"}
                        min={1}
                        max={30}
                        value={traceMinutes}
                        onChange={(e) =>
                            setTraceMinutes(Math.max(1, Math.min(30, Number(e.target.value) || 1)))
                        }
                        customSuffix={t("settings.troubleshooting.duration.suffix")}
                        disabled={!trace}
                    />
                </div>
            </div>

            <BottomBar>
                <Button variant={"primary"} size={"md"} onClick={run}>
                    {t("settings.troubleshooting.create")}
                </Button>
            </BottomBar>
        </SectionGroup>
    );
}

function ProgressSection({ stage, onCancel }: { stage: DebugStage; onCancel: () => void }) {
    const { t } = useTranslation();
    const cancelling = stage.kind === "cancelling";
    return (
        <StatusPanel
            variant={"loading"}
            title={stageLabel(stage, t)}
            description={t("settings.troubleshooting.progress.description")}
            actions={
                <Button variant={"secondary"} size={"xs"} onClick={onCancel} disabled={cancelling}>
                    {cancelling
                        ? t("settings.troubleshooting.cancelling")
                        : t("common.cancel")}
                </Button>
            }
        />
    );
}

function DoneResult({
    result,
    uploaded,
    onClose,
}: {
    result: DebugBundleResult;
    uploaded: boolean;
    onClose: () => void;
}) {
    const { t } = useTranslation();
    const showKey = uploaded && Boolean(result.uploadedKey);
    const uploadFailed = uploaded && !result.uploadedKey;
    const onRevealPath = () => {
        if (!result.path) return;
        void DebugSvc.RevealFile(result.path).catch(() => {});
    };
    return (
        <StatusPanel
            variant={"success"}
            title={
                showKey
                    ? t("settings.troubleshooting.done.uploadedTitle")
                    : t("settings.troubleshooting.done.savedTitle")
            }
            description={
                showKey
                    ? t("settings.troubleshooting.done.uploadedDescription")
                    : t("settings.troubleshooting.done.savedDescription")
            }
            actions={
                <>
                    <Button variant={"secondary"} size={"xs"} onClick={onClose}>
                        {t("common.close")}
                    </Button>
                    {showKey ? (
                        <Button variant={"primary"} size={"xs"} copy={result.uploadedKey}>
                            {t("settings.troubleshooting.done.copyKey")}
                        </Button>
                    ) : (
                        result.path && (
                            <Button variant={"primary"} size={"xs"} onClick={onRevealPath}>
                                <FolderOpen size={12} />
                                {t("settings.troubleshooting.done.openFolder")}
                            </Button>
                        )
                    )}
                </>
            }
        >
            <div className={"w-full max-w-xs mx-auto flex flex-col gap-3"}>
                {showKey && <Input value={result.uploadedKey} readOnly copy />}

                {result.path && !showKey && (
                    <Input
                        value={result.path}
                        readOnly
                        customSuffix={
                            <button
                                type={"button"}
                                onClick={onRevealPath}
                                className={"pointer-events-auto hover:text-white transition-all"}
                                aria-label={t("settings.troubleshooting.done.openFileLocation")}
                            >
                                <FolderOpen size={16} />
                            </button>
                        }
                    />
                )}

                {uploadFailed && (
                    <div
                        className={
                            "rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300"
                        }
                    >
                        {result.uploadFailureReason
                            ? t("settings.troubleshooting.uploadFailedWithReason", {
                                  reason: result.uploadFailureReason,
                              })
                            : t("settings.troubleshooting.uploadFailed")}
                    </div>
                )}
            </div>
        </StatusPanel>
    );
}

function BottomBar({ children }: { children: ReactNode }) {
    return (
        <div className={"absolute bottom-0 left-0 w-full"}>
            <div
                className={
                    "w-full flex justify-end gap-3 px-8 py-5 border-t border-nb-gray-900 bg-nb-gray-935"
                }
            >
                {children}
            </div>
        </div>
    );
}

const stageLabel = (stage: DebugStage, t: (key: string, options?: Record<string, unknown>) => string): string => {
    switch (stage.kind) {
        case "preparing-trace":
            return t("settings.troubleshooting.stage.preparingTrace");
        case "reconnecting":
            return t("settings.troubleshooting.stage.reconnecting");
        case "capturing": {
            const fmt = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
            return t("settings.troubleshooting.stage.capturing", {
                elapsed: fmt(stage.totalSec - stage.remainingSec),
                total: fmt(stage.totalSec),
            });
        }
        case "restoring-level":
            return t("settings.troubleshooting.stage.restoring");
        case "bundling":
            return t("settings.troubleshooting.stage.bundling");
        case "uploading":
            return t("settings.troubleshooting.stage.uploading");
        case "cancelling":
            return t("settings.troubleshooting.stage.cancelling");
        default:
            return "";
    }
};
