import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Connection as ConnectionSvc, Debug as DebugSvc } from "@bindings/services";
import type { DebugBundleResult } from "@bindings/services/models.js";
import i18next from "@/lib/i18n";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";
import { startConnection } from "@/lib/connection.ts";

const NETBIRD_UPLOAD_URL = "https://upload.debug.netbird.io/upload-url";
const TRACE_LOG_FILE_COUNT = 5;
const PLAIN_LOG_FILE_COUNT = 1;
const TRACE_LOG_LEVEL = "trace";
const DEFAULT_LOG_LEVEL = "info";

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

const isAbort = (e: unknown) => e instanceof DOMException && e.name === "AbortError";

const throwIfAborted = (signal: AbortSignal) => {
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
};

const setLogLevelBestEffort = async (level: string) => {
    try {
        await DebugSvc.SetLogLevel({ level });
    } catch (e) {
        console.warn("[DebugBundle] best-effort set log level failed", e);
    }
};

const stopCaptureBestEffort = async () => {
    try {
        await DebugSvc.StopBundleCapture();
    } catch (e) {
        console.warn("[DebugBundle] best-effort stop packet capture failed", e);
    }
};

type LevelState = { original: string; raised: boolean };
type CaptureState = { started: boolean };

type BundleOptions = {
    trace: boolean;
    capture: boolean;
    capturePackets: boolean;
    hasWindow: boolean;
    totalSec: number;
    uploadUrl: string;
    anonymize: boolean;
    systemInfo: boolean;
};

const startCaptureBestEffort = async (totalSec: number, pcap: CaptureState) => {
    try {
        // Mirror the CLI's safety margin: window + 30s, server caps at 10m.
        await DebugSvc.StartBundleCapture(totalSec + 30);
        pcap.started = true;
    } catch (e) {
        console.warn("[DebugBundle] start packet capture failed", e);
    }
};

const cleanupBestEffort = async (pcap: CaptureState, level: LevelState, restoreLevel: boolean) => {
    if (pcap.started) {
        await stopCaptureBestEffort();
        pcap.started = false;
    }
    if (restoreLevel && level.raised) {
        await setLogLevelBestEffort(level.original);
    }
};

const raiseToTrace = async (
    signal: AbortSignal,
    level: LevelState,
    setStage: (s: DebugStage) => void,
) => {
    setStage({ kind: "preparing-trace" });
    try {
        const cur = await DebugSvc.GetLogLevel();
        if (cur?.level) level.original = cur.level;
    } catch (e) {
        console.warn("[DebugBundle] read current log level failed", e);
    }
    throwIfAborted(signal);
    await DebugSvc.SetLogLevel({ level: TRACE_LOG_LEVEL });
    level.raised = true;
};

const cycleConnection = async (signal: AbortSignal, setStage: (s: DebugStage) => void) => {
    throwIfAborted(signal);
    setStage({ kind: "reconnecting" });
    try {
        await ConnectionSvc.Down();
    } catch (e) {
        console.warn("[DebugBundle] disconnect before capture failed", e);
    }
    throwIfAborted(signal);
    await startConnection(undefined, signal);
};

const restoreLogLevel = async (level: LevelState, setStage: (s: DebugStage) => void) => {
    setStage({ kind: "restoring-level" });
    try {
        await DebugSvc.SetLogLevel({ level: level.original });
        level.raised = false;
    } catch (e) {
        console.warn("[DebugBundle] restore log level failed", e);
    }
};

const waitCaptureWindow = async (
    signal: AbortSignal,
    setStage: (s: DebugStage) => void,
    totalSec: number,
) => {
    for (let remaining = totalSec; remaining > 0; remaining--) {
        setStage({ kind: "capturing", remainingSec: remaining, totalSec });
        await sleep(1000, signal);
    }
};

const runBundleFlow = async (
    signal: AbortSignal,
    opts: BundleOptions,
    level: LevelState,
    pcap: CaptureState,
    setStage: (s: DebugStage) => void,
    setLastBundlePath: (p: string) => void,
) => {
    if (opts.trace) {
        await raiseToTrace(signal, level, setStage);
    }
    throwIfAborted(signal);

    if (opts.capture) {
        await cycleConnection(signal, setStage);
    }
    throwIfAborted(signal);

    if (opts.hasWindow && opts.capturePackets) {
        await startCaptureBestEffort(opts.totalSec, pcap);
    }
    throwIfAborted(signal);

    if (opts.hasWindow) {
        await waitCaptureWindow(signal, setStage, opts.totalSec);
    }

    if (pcap.started) {
        await stopCaptureBestEffort();
        pcap.started = false;
    }

    if (level.raised) {
        await restoreLogLevel(level, setStage);
    }

    throwIfAborted(signal);
    setStage({ kind: "bundling" });
    const logFileCount = opts.trace ? TRACE_LOG_FILE_COUNT : PLAIN_LOG_FILE_COUNT;

    if (opts.uploadUrl) setStage({ kind: "uploading" });
    const result = await DebugSvc.Bundle({
        anonymize: opts.anonymize,
        systemInfo: opts.systemInfo,
        uploadUrl: opts.uploadUrl,
        logFileCount,
    });
    throwIfAborted(signal);
    if (result.path) setLastBundlePath(result.path);
    setStage({ kind: "done", result, uploadAttempted: Boolean(opts.uploadUrl) });
};

const useDebugBundle = () => {
    const [anonymize, setAnonymize] = useState(false);
    const [systemInfo, setSystemInfo] = useState(true);
    const [upload, setUpload] = useState(true);
    const [trace, setTrace] = useState(true);
    const [capture, setCapture] = useState(false);
    const [traceMinutes, setTraceMinutes] = useState(1);
    const [capturePackets, setCapturePackets] = useState(true);
    const [stage, setStage] = useState<DebugStage>({ kind: "idle" });
    const [lastBundlePath, setLastBundlePath] = useState<string>("");
    const abortRef = useRef<AbortController | null>(null);

    useEffect(() => {
        return () => {
            abortRef.current?.abort();
        };
    }, []);

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

        const totalSec = Math.max(1, Math.min(30, traceMinutes)) * 60;
        const level: LevelState = { original: DEFAULT_LOG_LEVEL, raised: false };
        const pcap: CaptureState = { started: false };
        const opts: BundleOptions = {
            trace,
            capture,
            capturePackets,
            hasWindow: capture && totalSec > 0,
            totalSec,
            uploadUrl: upload ? NETBIRD_UPLOAD_URL : "",
            anonymize,
            systemInfo,
        };

        try {
            await runBundleFlow(signal, opts, level, pcap, setStage, setLastBundlePath);
        } catch (e) {
            if (isAbort(e)) {
                setStage({ kind: "cancelling" });
                await cleanupBestEffort(pcap, level, true);
                setStage({ kind: "idle" });
                return;
            }
            await cleanupBestEffort(pcap, level, false);
            setStage({ kind: "idle" });
            await errorDialog({
                Title: i18next.t("settings.error.debugBundleTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            if (abortRef.current === ctrl) abortRef.current = null;
        }
    };

    const openBundleDir = () => {
        if (!lastBundlePath) return;
        DebugSvc.RevealFile(lastBundlePath).catch((err: unknown) =>
            console.error("[DebugBundleContext] reveal failed", err),
        );
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
        capture,
        setCapture,
        traceMinutes,
        setTraceMinutes,
        capturePackets,
        setCapturePackets,
        stage,
        isRunning,
        lastBundlePath,
        run,
        cancel,
        reset,
        openBundleDir,
    };
};

export type DebugBundleContextValue = ReturnType<typeof useDebugBundle>;

const DebugBundleContext = createContext<DebugBundleContextValue | null>(null);

export const DebugBundleProvider = ({ children }: { children: ReactNode }) => {
    const value = useDebugBundle();
    return <DebugBundleContext.Provider value={value}>{children}</DebugBundleContext.Provider>;
};

export const useDebugBundleContext = () => {
    const ctx = useContext(DebugBundleContext);
    if (!ctx) {
        throw new Error("useDebugBundleContext must be used inside DebugBundleProvider");
    }
    return ctx;
};
