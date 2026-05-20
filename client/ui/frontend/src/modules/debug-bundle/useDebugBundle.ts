import { useRef, useState } from "react";
import { Dialogs } from "@wailsio/runtime";
import {
    Connection as ConnectionSvc,
    Debug as DebugSvc,
} from "@bindings/services";
import type { DebugBundleResult } from "@bindings/services/models.js";
import i18next from "@/lib/i18n";
import { formatErrorMessage } from "@/lib/errors.ts";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";

const NETBIRD_UPLOAD_URL = "https://upload.debug.netbird.io/upload-url";
const TRACE_LOG_FILE_COUNT = 5;
const PLAIN_LOG_FILE_COUNT = 1;

export type DebugStage =
    | { kind: "idle" }
    | { kind: "preparing-trace" }
    | { kind: "reconnecting" }
    | { kind: "capturing"; remainingSec: number; totalSec: number }
    | { kind: "restoring-level" }
    | { kind: "bundling" }
    | { kind: "uploading" }
    | { kind: "cancelling" }
    | { kind: "done"; result: DebugBundleResult; uploadAttempted: boolean };

const sleep = (ms: number, signal: AbortSignal) =>
    new Promise<void>((resolve, reject) => {
        if (signal.aborted) {
            reject(new DOMException("aborted", "AbortError"));
            return;
        }
        const onAbort = () => {
            clearTimeout(id);
            reject(new DOMException("aborted", "AbortError"));
        };
        const id = setTimeout(() => {
            signal.removeEventListener("abort", onAbort);
            resolve();
        }, ms);
        signal.addEventListener("abort", onAbort);
    });

const isAbort = (e: unknown) =>
    e instanceof DOMException && e.name === "AbortError";

export const useDebugBundle = () => {
    const { activeProfile, username } = useProfile();
    const [anonymize, setAnonymize] = useState(false);
    const [systemInfo, setSystemInfo] = useState(true);
    const [upload, setUpload] = useState(true);
    const [trace, setTrace] = useState(true);
    const [traceMinutes, setTraceMinutes] = useState(1);
    const [stage, setStage] = useState<DebugStage>({ kind: "idle" });
    const [lastBundlePath, setLastBundlePath] = useState<string>("");
    const abortRef = useRef<AbortController | null>(null);

    const isRunning = stage.kind !== "idle" && stage.kind !== "done";

    const reset = () => setStage({ kind: "idle" });

    const cancel = () => {
        if (!abortRef.current || abortRef.current.signal.aborted) return;
        abortRef.current.abort();
        setStage({ kind: "cancelling" });
    };

    const run = async () => {
        const ctrl = new AbortController();
        abortRef.current = ctrl;
        const signal = ctrl.signal;
        const checkAbort = () => {
            if (signal.aborted)
                throw new DOMException("aborted", "AbortError");
        };

        const uploadUrl = upload ? NETBIRD_UPLOAD_URL : "";
        let originalLevel = "info";
        let raisedLevel = false;

        try {
            if (trace) {
                setStage({ kind: "preparing-trace" });
                try {
                    const cur = await DebugSvc.GetLogLevel();
                    if (cur?.level) originalLevel = cur.level;
                } catch {
                    // best effort
                }
                checkAbort();
                await DebugSvc.SetLogLevel({ level: "trace" });
                raisedLevel = true;

                checkAbort();
                setStage({ kind: "reconnecting" });
                try {
                    await ConnectionSvc.Down();
                } catch {
                    // already down
                }
                checkAbort();
                await ConnectionSvc.Up({
                    profileName: activeProfile,
                    username,
                });

                const totalSec =
                    Math.max(1, Math.min(30, traceMinutes)) * 60;
                for (let remaining = totalSec; remaining > 0; remaining--) {
                    setStage({
                        kind: "capturing",
                        remainingSec: remaining,
                        totalSec,
                    });
                    await sleep(1000, signal);
                }

                setStage({ kind: "restoring-level" });
                try {
                    await DebugSvc.SetLogLevel({ level: originalLevel });
                    raisedLevel = false;
                } catch {
                    // restore is best-effort
                }
            }

            checkAbort();
            setStage({ kind: "bundling" });
            const logFileCount = trace
                ? TRACE_LOG_FILE_COUNT
                : PLAIN_LOG_FILE_COUNT;

            if (uploadUrl) setStage({ kind: "uploading" });
            const result = await DebugSvc.Bundle({
                anonymize,
                systemInfo,
                uploadUrl,
                logFileCount,
            });
            checkAbort();
            if (result.path) setLastBundlePath(result.path);
            setStage({
                kind: "done",
                result,
                uploadAttempted: Boolean(uploadUrl),
            });
        } catch (e) {
            if (isAbort(e)) {
                if (raisedLevel) {
                    try {
                        await DebugSvc.SetLogLevel({ level: originalLevel });
                    } catch {
                        // best effort
                    }
                }
                setStage({ kind: "idle" });
                return;
            }
            setStage({ kind: "idle" });
            await Dialogs.Error({
                Title: i18next.t("settings.error.debugBundleTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            if (abortRef.current === ctrl) abortRef.current = null;
        }
    };

    const openBundleDir = () => {
        if (!lastBundlePath) return;
        void DebugSvc.RevealFile(lastBundlePath).catch(() => {});
    };

    return {
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
        lastBundlePath,
        run,
        cancel,
        reset,
        openBundleDir,
    };
};
