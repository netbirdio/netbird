import { useState } from "react";
import { Browser } from "@wailsio/runtime";
import { Check, Copy, FolderOpen, Loader2 } from "lucide-react";
import type { DebugBundleResult } from "@bindings/services/models.js";
import { Button } from "@/components/Button";
import FancyToggleSwitch from "@/components/FancyToggleSwitch";
import { Input } from "@/components/Input";
import { Label } from "@/components/Label";
import { cn } from "@/lib/cn";
import { SectionGroup } from "@/modules/settings/SettingsSection.tsx";
import {
    useDebugBundle,
    type DebugStage,
} from "@/modules/settings/useDebugBundle.ts";

export function SettingsTroubleshooting() {
    const bundle = useDebugBundle();
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
        stage,
        isRunning,
        run,
        reset,
    } = bundle;

    return (
        <SectionGroup title={"Debug bundle"}>
            <p className={"text-sm text-nb-gray-300 mb-2"}>
                A debug bundle helps NetBird support investigate connection
                problems. It's a zip file with logs and system details from
                this device.
            </p>

            <FancyToggleSwitch
                value={anonymize}
                onChange={setAnonymize}
                label={"Anonymize personal data"}
                helpText={
                    "Replace IPs, hostnames, and peer names before saving."
                }
                disabled={isRunning}
            />
            <FancyToggleSwitch
                value={systemInfo}
                onChange={setSystemInfo}
                label={"Include system info"}
                helpText={
                    "Include OS, kernel, network interfaces, and routing tables."
                }
                disabled={isRunning}
            />
            <FancyToggleSwitch
                value={upload}
                onChange={setUpload}
                label={"Send to NetBird support"}
                helpText={
                    "Uploads the bundle directly. You'll get a key to share with us."
                }
                disabled={isRunning}
            />
            <FancyToggleSwitch
                value={trace}
                onChange={setTrace}
                label={"Capture detailed (trace) logs"}
                helpText={
                    "Restart NetBird with extra logging for a few minutes, then create the bundle. NetBird will briefly disconnect."
                }
                disabled={isRunning}
            >
                <div className={"flex items-center gap-3 max-w-sm"}>
                    <Label as={"div"} className={"!mb-0"}>
                        Capture for
                    </Label>
                    <div className={"w-24"}>
                        <Input
                            type={"number"}
                            min={1}
                            max={30}
                            value={traceMinutes}
                            onChange={(e) =>
                                setTraceMinutes(
                                    Math.max(
                                        1,
                                        Math.min(
                                            30,
                                            Number(e.target.value) || 1,
                                        ),
                                    ),
                                )
                            }
                            customSuffix={
                                <span className={"text-nb-gray-400"}>min</span>
                            }
                            disabled={isRunning}
                        />
                    </div>
                </div>
            </FancyToggleSwitch>

            <div className={"flex items-center gap-3 mt-2"}>
                <Button
                    variant={"primary"}
                    size={"md"}
                    onClick={run}
                    disabled={isRunning}
                >
                    {isRunning ? "Creating bundle…" : "Create bundle"}
                </Button>
                {stage.kind === "error" && (
                    <Button
                        variant={"secondary"}
                        size={"md"}
                        onClick={reset}
                    >
                        Try again
                    </Button>
                )}
            </div>

            <BundleStatus stage={stage} />
        </SectionGroup>
    );
}

function BundleStatus({ stage }: { stage: DebugStage }) {
    if (stage.kind === "idle") return null;

    if (
        stage.kind === "preparing-trace" ||
        stage.kind === "reconnecting" ||
        stage.kind === "capturing" ||
        stage.kind === "restoring-level" ||
        stage.kind === "bundling" ||
        stage.kind === "uploading"
    ) {
        return (
            <div
                className={
                    "mt-4 flex items-center gap-3 rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-3"
                }
            >
                <Loader2
                    className={"animate-spin text-netbird shrink-0"}
                    size={18}
                />
                <p className={"text-sm text-nb-gray-200"}>
                    {stageLabel(stage)}
                </p>
            </div>
        );
    }

    if (stage.kind === "error") {
        return (
            <div
                className={
                    "mt-4 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
                }
            >
                {stage.message}
            </div>
        );
    }

    return <BundleResult result={stage.result} uploaded={stage.uploadAttempted} />;
}

function stageLabel(stage: DebugStage): string {
    switch (stage.kind) {
        case "preparing-trace":
            return "Switching to trace logging…";
        case "reconnecting":
            return "Reconnecting NetBird…";
        case "capturing": {
            const fmt = (s: number) =>
                `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
            return `Capturing logs — ${fmt(
                stage.totalSec - stage.remainingSec,
            )} / ${fmt(stage.totalSec)}`;
        }
        case "restoring-level":
            return "Restoring previous log level…";
        case "bundling":
            return "Building bundle…";
        case "uploading":
            return "Uploading to NetBird…";
        default:
            return "";
    }
}

function BundleResult({
    result,
    uploaded,
}: {
    result: DebugBundleResult;
    uploaded: boolean;
}) {
    const uploadFailed = uploaded && !result.uploadedKey;
    return (
        <div className={"mt-4 flex flex-col gap-3"}>
            {uploaded && result.uploadedKey && (
                <div
                    className={
                        "rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-4"
                    }
                >
                    <p className={"text-sm font-medium mb-1"}>
                        Bundle uploaded
                    </p>
                    <p className={"text-xs text-nb-gray-400 mb-3"}>
                        Share this key with NetBird support so they can find
                        your bundle.
                    </p>
                    <CopyableValue value={result.uploadedKey} mono large />
                </div>
            )}

            {uploadFailed && (
                <div
                    className={
                        "rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
                    }
                >
                    Upload failed
                    {result.uploadFailureReason
                        ? `: ${result.uploadFailureReason}`
                        : "."}{" "}
                    The bundle is still saved locally.
                </div>
            )}

            {result.path && (
                <div
                    className={
                        "rounded-md border border-nb-gray-800 bg-nb-gray-920 px-4 py-3"
                    }
                >
                    <p className={"text-xs text-nb-gray-400 mb-2"}>
                        {uploaded && result.uploadedKey
                            ? "A local copy was also saved at:"
                            : "Bundle saved to:"}
                    </p>
                    <CopyableValue value={result.path} mono />
                    <p className={"text-xs text-nb-gray-500 mt-2"}>
                        You may need admin privileges to open this file.
                    </p>
                </div>
            )}
        </div>
    );
}

function CopyableValue({
    value,
    mono = false,
    large = false,
}: {
    value: string;
    mono?: boolean;
    large?: boolean;
}) {
    const [copied, setCopied] = useState(false);
    const onCopy = async () => {
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        } catch {
            // ignore
        }
    };
    const onReveal = () => {
        void Browser.OpenURL(`file://${value}`).catch(() => {});
    };
    return (
        <div className={"flex items-center gap-2"}>
            <code
                className={cn(
                    "flex-1 min-w-0 truncate rounded bg-nb-gray-900 px-3 py-2 border border-nb-gray-800",
                    mono && "font-mono",
                    large ? "text-sm" : "text-xs",
                )}
            >
                {value}
            </code>
            <button
                type={"button"}
                onClick={onCopy}
                className={
                    "p-2 rounded-md border border-nb-gray-800 text-nb-gray-300 hover:text-white hover:bg-nb-gray-900"
                }
                aria-label={"Copy"}
            >
                {copied ? <Check size={14} /> : <Copy size={14} />}
            </button>
            {value.startsWith("/") || value.match(/^[A-Za-z]:\\/) ? (
                <button
                    type={"button"}
                    onClick={onReveal}
                    className={
                        "p-2 rounded-md border border-nb-gray-800 text-nb-gray-300 hover:text-white hover:bg-nb-gray-900"
                    }
                    aria-label={"Reveal"}
                >
                    <FolderOpen size={14} />
                </button>
            ) : null}
        </div>
    );
}
