import type { ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";
import { CircleCheckBig, FolderOpen, Loader2 } from "lucide-react";
import { Debug as DebugSvc } from "@bindings/services";
import type { DebugBundleResult } from "@bindings/services/models.js";
import { Button } from "@/components/buttons/Button";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import HelpText from "@/components/typography/HelpText.tsx";
import { Input } from "@/components/inputs/Input";
import { Label } from "@/components/typography/Label";
import { SquareIcon } from "@/components/SquareIcon";
import { cn } from "@/lib/cn";
import type { DebugStage } from "@/contexts/DebugBundleContext";
import { useDebugBundleContext } from "@/contexts/DebugBundleContext";
import { SectionGroup, SettingsBottomBar } from "@/modules/settings/SettingsSection.tsx";

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
            <DoneResult result={stage.result} uploaded={stage.uploadAttempted} onClose={reset} />
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

            <SettingsBottomBar>
                <Button variant={"primary"} size={"md"} onClick={run}>
                    {t("settings.troubleshooting.create")}
                </Button>
            </SettingsBottomBar>
        </SectionGroup>
    );
}

function CenteredPanel({ children }: Readonly<{ children: ReactNode }>) {
    return (
        <div
            className={
                "absolute inset-0 flex flex-col items-center justify-center gap-5 p-8 text-center"
            }
        >
            {children}
        </div>
    );
}

function ProgressSection({
    stage,
    onCancel,
}: Readonly<{ stage: DebugStage; onCancel: () => void }>) {
    const { t } = useTranslation();
    const cancelling = stage.kind === "cancelling";
    return (
        <CenteredPanel>
            <SquareIcon icon={Loader2} className={"[&_svg]:animate-spin"} />

            <div className={"flex flex-col items-center gap-2 max-w-xs"}>
                <DialogHeading className={"text-balance"}>{stageLabel(stage, t)}</DialogHeading>
                <DialogDescription>
                    {t("settings.troubleshooting.progress.description")}
                </DialogDescription>
            </div>

            <DialogActions className={"max-w-[220px]"}>
                <Button
                    autoFocus
                    variant={"secondary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={onCancel}
                    disabled={cancelling}
                >
                    {t("common.cancel")}
                </Button>
            </DialogActions>
        </CenteredPanel>
    );
}

function DoneResult({
    result,
    uploaded,
    onClose,
}: Readonly<{
    result: DebugBundleResult;
    uploaded: boolean;
    onClose: () => void;
}>) {
    const { t } = useTranslation();
    const showKey = uploaded && Boolean(result.uploadedKey);
    const uploadFailed = uploaded && !result.uploadedKey;
    const onRevealPath = () => {
        if (!result.path) return;
        DebugSvc.RevealFile(result.path).catch((err: unknown) =>
            console.error("reveal debug bundle file", err),
        );
    };
    return (
        <CenteredPanel>
            <SquareIcon icon={CircleCheckBig} className={"[&_svg]:text-green-500"} />

            <div className={"flex flex-col items-center gap-2 max-w-xs"}>
                <DialogHeading className={"text-balance"}>
                    {showKey
                        ? t("settings.troubleshooting.done.uploadedTitle")
                        : t("settings.troubleshooting.done.savedTitle")}
                </DialogHeading>
                <DialogDescription>
                    {showKey
                        ? t("settings.troubleshooting.done.uploadedDescription")
                        : t("settings.troubleshooting.done.savedDescription")}
                </DialogDescription>
            </div>

            <div className={"w-full max-w-xs flex flex-col gap-3"}>
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

            <DialogActions className={"max-w-[220px]"}>
                {showKey ? (
                    <Button
                        autoFocus
                        variant={"primary"}
                        size={"md"}
                        className={"w-full"}
                        copy={result.uploadedKey}
                    >
                        {t("settings.troubleshooting.done.copyKey")}
                    </Button>
                ) : (
                    result.path && (
                        <Button
                            autoFocus
                            variant={"primary"}
                            size={"md"}
                            className={"w-full"}
                            onClick={onRevealPath}
                        >
                            <FolderOpen size={14} />
                            {t("settings.troubleshooting.done.openFolder")}
                        </Button>
                    )
                )}
                <Button variant={"secondary"} size={"md"} className={"w-full"} onClick={onClose}>
                    {t("common.close")}
                </Button>
            </DialogActions>
        </CenteredPanel>
    );
}

const stageLabel = (
    stage: DebugStage,
    t: (key: string, options?: Record<string, unknown>) => string,
): string => {
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
