import { useState } from "react";
import {
    Connection as ConnectionSvc,
    Debug as DebugSvc,
} from "@bindings/services";
import type { DebugBundleResult } from "@bindings/services/models.js";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";

const NETBIRD_UPLOAD_URL = "https://debug.netbird.io/upload";
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
    | { kind: "done"; result: DebugBundleResult; uploadAttempted: boolean }
    | { kind: "error"; message: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const useDebugBundle = () => {
    const { activeProfile, username } = useProfile();
    const [anonymize, setAnonymize] = useState(true);
    const [systemInfo, setSystemInfo] = useState(true);
    const [upload, setUpload] = useState(false);
    const [trace, setTrace] = useState(false);
    const [traceMinutes, setTraceMinutes] = useState(3);
    const [stage, setStage] = useState<DebugStage>({ kind: "idle" });

    const isRunning =
        stage.kind !== "idle" &&
        stage.kind !== "done" &&
        stage.kind !== "error";

    const reset = () => setStage({ kind: "idle" });

    const run = async () => {
        const uploadUrl = upload ? NETBIRD_UPLOAD_URL : "";
        try {
            let originalLevel = "info";
            if (trace) {
                setStage({ kind: "preparing-trace" });
                try {
                    const cur = await DebugSvc.GetLogLevel();
                    if (cur?.level) originalLevel = cur.level;
                } catch {
                    // best effort
                }
                await DebugSvc.SetLogLevel({ level: "trace" });

                setStage({ kind: "reconnecting" });
                try {
                    await ConnectionSvc.Down();
                } catch {
                    // already down
                }
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
                    await sleep(1000);
                }

                setStage({ kind: "restoring-level" });
                try {
                    await DebugSvc.SetLogLevel({ level: originalLevel });
                } catch {
                    // restore is best-effort
                }
            }

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
            setStage({
                kind: "done",
                result,
                uploadAttempted: Boolean(uploadUrl),
            });
        } catch (e) {
            setStage({ kind: "error", message: String(e) });
        }
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
        run,
        reset,
    };
};
