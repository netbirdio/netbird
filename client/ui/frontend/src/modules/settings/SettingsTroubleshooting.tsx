import { useId, type ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";
import { CircleCheckBig, FolderOpen, Loader2 } from "lucide-react";
import { Browser } from "@wailsio/runtime";
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
import { formatRemaining } from "@/lib/formatters";
import type { DebugStage } from "@/contexts/DebugBundleContext";
import { useDebugBundleContext } from "@/contexts/DebugBundleContext";
import { SectionGroup, SettingsBottomBar } from "@/modules/settings/SettingsSection.tsx";

const SUPPORT_DOCS_URL = "https://docs.netbird.io/help/report-bug-issues";

export function SettingsTroubleshooting() {
    const { t } = useTranslation();
    const durationId = useId();
    const {
        anonymize,
        setAnonymize,
        systemInfo,
        setSystemInfo,
        upload,
        setUpload,
        trace,
        setTrace,
        capture,
        setCapture,
        traceMinutes,
        setTraceMinutes,
        capturePackets,
        setCapturePackets,
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
            <FancyToggleSwitch
                value={capture}
                onChange={setCapture}
                label={t("settings.troubleshooting.capture.label")}
                helpText={t("settings.troubleshooting.capture.help")}
            />
            <div className={"flex flex-col gap-4"}>
                <FancyToggleSwitch
                    value={capturePackets}
                    onChange={setCapturePackets}
                    label={t("settings.troubleshooting.packets.label")}
                    helpText={t("settings.troubleshooting.packets.help")}
                    disabled={!capture}
                />
                <div
                    className={"flex items-center justify-between gap-6"}
                    {...(capture ? {} : { inert: "" })}
                >
                    <div className={"max-w-md flex-1"}>
                        <Label htmlFor={durationId} disabled={!capture}>
                            {t("settings.troubleshooting.duration.label")}
                        </Label>
                        <HelpText margin={false} disabled={!capture}>
                            {t("settings.troubleshooting.duration.help")}
                        </HelpText>
                    </div>
                    <div className={"w-40 shrink-0"}>
                        <Input
                            id={durationId}
                            type={"number"}
                            min={1}
                            max={30}
                            value={traceMinutes}
                            onChange={(e) =>
                                setTraceMinutes(
                                    Math.max(1, Math.min(30, Number(e.target.value) || 1)),
                                )
                            }
                            customSuffix={t("settings.troubleshooting.duration.suffix")}
                            disabled={!capture}
                        />
                    </div>
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

            <div className={"flex max-w-sm flex-col items-center gap-2"}>
                <DialogHeading className={"text-balance"}>{stageLabel(stage, t)}</DialogHeading>
                <DialogDescription>
                    {t("settings.troubleshooting.progress.description")}
                </DialogDescription>
            </div>

            {stage.kind === "capturing" && (
                <div
                    className={
                        "font-mono text-2xl font-semibold tabular-nums tracking-wider text-nb-gray-50"
                    }
                    aria-live={"polite"}
                >
                    {formatRemaining(stage.remainingSec)}
                </div>
            )}

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

            <div className={"flex max-w-sm flex-col items-center gap-2"}>
                <DialogHeading className={"text-balance"}>
                    {showKey
                        ? t("settings.troubleshooting.done.uploadedTitle")
                        : t("settings.troubleshooting.done.savedTitle")}
                </DialogHeading>
                <DialogDescription>
                    {showKey ? (
                        <Trans
                            i18nKey={"settings.troubleshooting.done.uploadedDescription"}
                            components={{
                                docs: (
                                    <a
                                        href={SUPPORT_DOCS_URL}
                                        aria-label={t("settings.about.community.documentation")}
                                        onClick={(e) => {
                                            e.preventDefault();
                                            Browser.OpenURL(SUPPORT_DOCS_URL).catch(() =>
                                                globalThis.open(SUPPORT_DOCS_URL, "_blank"),
                                            );
                                        }}
                                        className={"text-netbird hover:underline"}
                                    >
                                        {/* content is provided by <Trans> */}
                                        <span />
                                    </a>
                                ),
                            }}
                        />
                    ) : (
                        t("settings.troubleshooting.done.savedDescription")
                    )}
                </DialogDescription>
            </div>

            <div className={"flex w-full max-w-sm flex-col gap-3"}>
                {showKey && <Input value={result.uploadedKey} readOnly copy />}

                {result.path && !showKey && (
                    <Input
                        value={result.path}
                        readOnly
                        aria-label={t("settings.troubleshooting.done.savedTitle")}
                        customSuffix={
                            <button
                                type={"button"}
                                onClick={onRevealPath}
                                className={"pointer-events-auto transition-all hover:text-white"}
                                aria-label={t("settings.troubleshooting.done.openFileLocation")}
                            >
                                <FolderOpen size={16} aria-hidden={"true"} />
                            </button>
                        }
                    />
                )}

                {uploadFailed && (
                    <div
                        role={"alert"}
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
                            <FolderOpen size={14} aria-hidden={"true"} />
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
        case "reconnecting":
            return t("settings.troubleshooting.stage.reconnecting");
        case "capturing":
            return t("settings.troubleshooting.stage.capturing");
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
