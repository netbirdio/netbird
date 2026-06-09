import { UILog } from "@bindings/services";

type Level = "trace" | "debug" | "info" | "warn" | "error";

const METHOD_LEVELS: Record<string, Level> = {
    trace: "trace",
    debug: "debug",
    log: "info",
    info: "info",
    warn: "warn",
    error: "error",
};

const IGNORED_SOURCES = new Set(["welcome.ts"]);

const RATE_LIMIT = 50;
const RATE_WINDOW_MS = 1000;

let installed = false;
let inForward = false;
let windowStart = 0;
let windowCount = 0;

function format(args: unknown[]): string {
    return args
        .map((a) => {
            if (typeof a === "string") return a;
            if (a instanceof Error) return a.stack || a.message;
            try {
                return JSON.stringify(a);
            } catch {
                return String(a);
            }
        })
        .join(" ");
}

function callerSource(): string {
    const stack = new Error().stack;
    if (!stack) return "";
    for (const line of stack.split("\n").slice(1)) {
        if (line.includes("/logs.ts")) continue;
        const m = /([^/\\() ]+\.[a-z]+):(\d+):\d+/i.exec(line);
        if (m) return `${m[1]}:${m[2]}`;
    }
    return "";
}

function forward(level: Level, args: unknown[]) {
    if (inForward) return;
    inForward = true;
    try {
        const now = Date.now();
        if (now - windowStart >= RATE_WINDOW_MS) {
            windowStart = now;
            windowCount = 0;
        }
        if (++windowCount > RATE_LIMIT) return;

        const source = callerSource();
        if (IGNORED_SOURCES.has(source.split(":")[0])) return;
        // Don't touch console here — it would recurse back into forward().
        UILog.Log(level, source, format(args)).catch(() => {});
    } catch {
    } finally {
        inForward = false;
    }
}

export function initLogForwarding() {
    if (installed) return;
    installed = true;

    const c = console as unknown as Record<string, (...a: unknown[]) => void>;
    for (const [method, level] of Object.entries(METHOD_LEVELS)) {
        const original = c[method]?.bind(console);
        c[method] = (...args: unknown[]) => {
            original?.(...args);
            forward(level, args);
        };
    }

    globalThis.addEventListener("error", (e) => {
        forward("error", [`uncaught error: ${e.message}`, e.error ?? ""]);
    });
    globalThis.addEventListener("unhandledrejection", (e) => {
        forward("error", ["unhandled promise rejection:", e.reason]);
    });
}
