import type { ReactNode } from "react";
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

    if (stage.kind === "done" || stage.kind === "error") {
        return <ResultSection stage={stage} onClose={reset} />;
    }
    if (stage.kind !== "idle") {
        return <ProgressSection stage={stage} onCancel={cancel} />;
    }

    return (
        <SectionGroup title={"Debug bundle"}>
            <HelpText className={"-mt-2 mb-2"}>
                A debug bundle helps NetBird support investigate connection problems. <br /> It's a
                .zip file with logs, system details and debug information from your device.
            </HelpText>

            <FancyToggleSwitch
                value={anonymize}
                onChange={setAnonymize}
                label={"Anonymize Sensitive Information"}
                helpText={"Hides public IP addresses and non-NetBird domains from logs."}
            />
            <FancyToggleSwitch
                value={systemInfo}
                onChange={setSystemInfo}
                label={"Include System Information"}
                helpText={"Include OS, kernel, network interfaces, and routing tables."}
            />
            <FancyToggleSwitch
                value={upload}
                onChange={setUpload}
                label={"Upload Bundle to NetBird Servers"}
                helpText={
                    "Securely uploads the bundle and returns an upload key. Share the key with NetBird support over GitHub or Slack instead of attaching the file directly."
                }
            />
            <FancyToggleSwitch
                value={trace}
                onChange={setTrace}
                label={"Capture Trace Logs"}
                helpText={
                    "Raises logging to TRACE and cycles NetBird up and down to capture connection logs. The previous level is restored after the bundle is built."
                }
            />
            <div
                className={cn(
                    "flex items-center gap-6 justify-between",
                    !trace && "opacity-50 pointer-events-none",
                )}
            >
                <div className={"flex-1 max-w-md"}>
                    <Label as={"div"}>Capture Duration</Label>
                    <HelpText margin={false}>
                        How long to capture trace logs before generating the bundle.
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
                        customSuffix={"Minute(s)"}
                        disabled={!trace}
                    />
                </div>
            </div>

            <BottomBar>
                <Button variant={"primary"} size={"md"} onClick={run}>
                    Create Bundle
                </Button>
            </BottomBar>
        </SectionGroup>
    );
}

function ProgressSection({ stage, onCancel }: { stage: DebugStage; onCancel: () => void }) {
    const cancelling = stage.kind === "cancelling";
    return (
        <StatusPanel
            variant={"loading"}
            title={stageLabel(stage)}
            description={
                "Collecting logs, system details, and connection state. This usually takes a moment — keep this window open until it completes."
            }
            actions={
                <Button variant={"secondary"} size={"xs"} onClick={onCancel} disabled={cancelling}>
                    {cancelling ? "Cancelling…" : "Cancel"}
                </Button>
            }
        />
    );
}

function ResultSection({
    stage,
    onClose,
}: {
    stage: Extract<DebugStage, { kind: "done" } | { kind: "error" }>;
    onClose: () => void;
}) {
    if (stage.kind === "error") {
        return (
            <StatusPanel
                variant={"error"}
                title={"Bundle failed"}
                description={stage.message}
                actions={
                    <Button variant={"secondary"} size={"xs"} onClick={onClose}>
                        Close
                    </Button>
                }
            />
        );
    }
    return <DoneResult result={stage.result} uploaded={stage.uploadAttempted} onClose={onClose} />;
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
    const showKey = uploaded && Boolean(result.uploadedKey);
    const uploadFailed = uploaded && !result.uploadedKey;
    const onRevealPath = () => {
        if (!result.path) return;
        void DebugSvc.RevealFile(result.path).catch(() => {});
    };
    return (
        <StatusPanel
            variant={"success"}
            title={showKey ? "Debug bundle successfully uploaded!" : "Bundle saved"}
            description={
                showKey
                    ? "Share the upload key below with NetBird support. A local copy was also saved on your device."
                    : "Your debug bundle has been saved locally."
            }
            actions={
                <>
                    <Button variant={"secondary"} size={"xs"} onClick={onClose}>
                        Close
                    </Button>
                    {showKey ? (
                        <Button variant={"primary"} size={"xs"} copy={result.uploadedKey}>
                            Copy Key
                        </Button>
                    ) : (
                        result.path && (
                            <Button variant={"primary"} size={"xs"} onClick={onRevealPath}>
                                <FolderOpen size={12} />
                                Open Folder
                            </Button>
                        )
                    )}
                </>
            }
        >
            <div className={"w-full max-w-xs mx-auto flex flex-col gap-3"}>
                {showKey && <Input value={result.uploadedKey} readOnly copy />}

                {result.path && (
                    <Input
                        value={result.path}
                        readOnly
                        customSuffix={
                            <button
                                type={"button"}
                                onClick={onRevealPath}
                                className={"pointer-events-auto hover:text-white transition-all"}
                                aria-label={"Open file location"}
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
                        Upload failed
                        {result.uploadFailureReason ? `: ${result.uploadFailureReason}` : "."} The
                        bundle is still saved locally.
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

const stageLabel = (stage: DebugStage): string => {
    switch (stage.kind) {
        case "preparing-trace":
            return "Switching to trace logging…";
        case "reconnecting":
            return "Reconnecting NetBird…";
        case "capturing": {
            const fmt = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
            return `Capturing logs — ${fmt(
                stage.totalSec - stage.remainingSec,
            )} / ${fmt(stage.totalSec)}`;
        }
        case "restoring-level":
            return "Restoring previous log level…";
        case "bundling":
            return "Generating debug bundle…";
        case "uploading":
            return "Uploading to NetBird…";
        case "cancelling":
            return "Cancelling…";
        default:
            return "";
    }
};
