import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Loader2, XCircle } from "lucide-react";
import { Update as UpdateSvc, WindowManager } from "@bindings/services";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";

const TIMEOUT_MS = 15 * 60 * 1000;
const POLL_INTERVAL_MS = 2000;
// Sustained gRPC failure during install is taken as success (installer restarts the daemon mid-flight).
const DAEMON_DOWN_GRACE_MS = 5000;
const WINDOW_WIDTH = 360;

type Phase =
    | { kind: "running" }
    | { kind: "timeout" }
    | { kind: "canceled" }
    | { kind: "failed"; message: string };

export default function UpdateInProgressDialog() {
    const { t } = useTranslation();
    const [params] = useSearchParams();
    const version = params.get("version") ?? "";
    const [phase, setPhase] = useState<Phase>({ kind: "running" });
    const phaseRef = useRef(phase);
    phaseRef.current = phase;
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);

    useEffect(() => {
        let cancelled = false;
        let done = false;
        let timer: ReturnType<typeof setTimeout> | null = null;
        const start = Date.now();
        let firstUnreachableAt: number | null = null;

        const poll = async () => {
            if (cancelled || done) return;
            if (phaseRef.current.kind !== "running") return;

            if (Date.now() - start > TIMEOUT_MS) {
                done = true;
                setPhase({ kind: "timeout" });
                return;
            }

            try {
                const r = await UpdateSvc.GetInstallerResult();
                if (cancelled || done || phaseRef.current.kind !== "running") return;
                firstUnreachableAt = null;
                if (r.success) {
                    done = true;
                    UpdateSvc.Quit().catch(console.error);
                    return;
                }
                if (r.errorMsg) {
                    done = true;
                    setPhase(mapInstallError(r.errorMsg));
                    return;
                }
            } catch {
                if (cancelled || done || phaseRef.current.kind !== "running") return;
                const now = Date.now();
                if (firstUnreachableAt === null) {
                    firstUnreachableAt = now;
                } else if (now - firstUnreachableAt >= DAEMON_DOWN_GRACE_MS) {
                    done = true;
                    UpdateSvc.Quit().catch(console.error);
                    return;
                }
            }

            if (!cancelled && !done) {
                timer = setTimeout(poll, POLL_INTERVAL_MS);
            }
        };

        timer = setTimeout(poll, POLL_INTERVAL_MS);

        return () => {
            cancelled = true;
            if (timer) clearTimeout(timer);
        };
    }, []);

    const isError = phase.kind !== "running";
    const errorInfo = isError ? classifyPhase(phase, version, t) : null;
    const updatingHeading = version
        ? t("update.overlay.updatingVersion", { version })
        : t("update.overlay.updating");

    return (
        <ConfirmDialog ref={contentRef}>
            {isError ? (
                <SquareIcon icon={XCircle} className={"bg-red-500 [&_svg]:text-white"} />
            ) : (
                <SquareIcon icon={Loader2} className={"[&_svg]:animate-spin"} />
            )}

            <div className={"flex flex-col items-center gap-2"}>
                <DialogHeading className={"text-balance"}>
                    {errorInfo ? errorInfo.title : updatingHeading}
                </DialogHeading>
                <DialogDescription>
                    {errorInfo ? (
                        <>
                            {errorInfo.description}
                            {errorInfo.message && (
                                <>
                                    <br />
                                    <span className={"first-letter:uppercase"}>
                                        {errorInfo.message}
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
                        autoFocus
                        variant={"secondary"}
                        size={"md"}
                        className={"w-full"}
                        onClick={() => WindowManager.CloseInstallProgress().catch(console.error)}
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
    if (m === "") return { kind: "failed", message: "" };
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
