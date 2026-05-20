import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Loader2, XCircle } from "lucide-react";
import { Update as UpdateSvc, WindowManager } from "@bindings/services";
import { Button } from "@/components/Button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DialogActions } from "@/components/DialogActions";
import { DialogDescription } from "@/components/DialogDescription";
import { DialogHeading } from "@/components/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { useAutoSizeWindow } from "@/lib/useAutoSizeWindow";

const TIMEOUT_MS = 15 * 60 * 1000;
const POLL_INTERVAL_MS = 2000;
// Sustained gRPC failure during install is taken as success — the daemon
// gets restarted by the installer mid-flight, mirroring the legacy Fyne
// UI's branch in client/ui/update.go.
const DAEMON_DOWN_GRACE_MS = 5000;
const WINDOW_WIDTH = 360;

type Phase =
    | { kind: "running" }
    | { kind: "timeout" }
    | { kind: "canceled" }
    | { kind: "failed"; message: string };

export default function InstallProgressDialog() {
    const { t } = useTranslation();
    const [params] = useSearchParams();
    const version = params.get("version") ?? "";
    const [phase, setPhase] = useState<Phase>({ kind: "running" });
    const phaseRef = useRef(phase);
    phaseRef.current = phase;
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);

    useEffect(() => {
        let cancelled = false;
        const start = Date.now();
        let firstUnreachableAt: number | null = null;

        const timer = setInterval(async () => {
            if (cancelled) return;
            if (phaseRef.current.kind !== "running") return;

            if (Date.now() - start > TIMEOUT_MS) {
                clearInterval(timer);
                setPhase({ kind: "timeout" });
                return;
            }

            try {
                const r = await UpdateSvc.GetInstallerResult();
                firstUnreachableAt = null;
                if (r.success) {
                    clearInterval(timer);
                    UpdateSvc.Quit();
                    return;
                }
                if (r.errorMsg) {
                    clearInterval(timer);
                    setPhase(mapInstallError(r.errorMsg));
                }
            } catch {
                const now = Date.now();
                if (firstUnreachableAt === null) {
                    firstUnreachableAt = now;
                } else if (now - firstUnreachableAt >= DAEMON_DOWN_GRACE_MS) {
                    clearInterval(timer);
                    UpdateSvc.Quit();
                }
            }
        }, POLL_INTERVAL_MS);

        return () => {
            cancelled = true;
            clearInterval(timer);
        };
    }, []);

    const isError = phase.kind !== "running";
    const errorInfo = isError ? classifyPhase(phase, version, t) : null;

    return (
        <ConfirmDialog ref={contentRef}>
            {isError ? (
                <SquareIcon
                    icon={XCircle}
                    className={"mt-4 bg-red-500 [&_svg]:text-white"}
                />
            ) : (
                <SquareIcon icon={Loader2} className={"mt-4 [&_svg]:animate-spin"} />
            )}

            <div className={"flex flex-col items-center gap-2"}>
                <DialogHeading className={"text-balance"}>
                    {isError
                        ? errorInfo!.title
                        : version
                            ? t("update.overlay.updatingVersion", { version })
                            : t("update.overlay.updating")}
                </DialogHeading>
                <DialogDescription>
                    {isError ? (
                        <>
                            {errorInfo!.description}
                            {errorInfo!.message && (
                                <>
                                    <br />
                                    <span className={"first-letter:uppercase"}>
                                        {errorInfo!.message}
                                    </span>
                                </>
                            )}
                        </>
                    ) : (
                        t("update.overlay.description")
                    )}
                </DialogDescription>
            </div>

            {isError && (
                <DialogActions>
                    <Button
                        variant={"secondary"}
                        size={"md"}
                        className={"w-full"}
                        onClick={() =>
                            WindowManager.CloseInstallProgress().catch(console.error)
                        }
                    >
                        {t("common.close")}
                    </Button>
                </DialogActions>
            )}
        </ConfirmDialog>
    );
}

function mapInstallError(msg: string): Phase {
    const m = msg.trim().toLowerCase();
    if (m === "") return { kind: "failed", message: "unknown update error" };
    if (m.includes("deadline exceeded") || m.includes("timeout") || m.includes("timed out")) {
        return { kind: "timeout" };
    }
    if (m.includes("canceled") || m.includes("cancelled") || m.includes("cancel")) {
        return { kind: "canceled" };
    }
    return { kind: "failed", message: msg };
}

type Variant = { title: string; description: string; message?: string };

function classifyPhase(
    phase: Phase,
    version: string,
    t: (key: string, options?: Record<string, unknown>) => string,
): Variant {
    const target = version
        ? t("update.overlay.error.targetVersion", { version })
        : t("update.overlay.error.targetFallback");
    switch (phase.kind) {
        case "timeout":
            return {
                title: t("update.overlay.error.timeoutTitle"),
                description: t("update.overlay.error.timeoutDescription", { target }),
            };
        case "canceled":
            return {
                title: t("update.overlay.error.canceledTitle"),
                description: t("update.overlay.error.canceledDescription", { target }),
            };
        case "failed":
            return {
                title: t("update.overlay.error.failTitle"),
                description: t("update.overlay.error.failDescription", { target }),
                message: phase.message || t("update.overlay.error.unknownMessage"),
            };
        default:
            return { title: "", description: "" };
    }
}
