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

function describeCause(rawCause: unknown): string {
    if (rawCause instanceof Error) return `${rawCause.name}: ${rawCause.message}`;
    if (typeof rawCause === "object" && rawCause !== null) {
        try {
            return JSON.stringify(rawCause);
        } catch {
            // Circular ref — fall through to a tag instead of "[object Object]".
            return `<${rawCause.constructor?.name ?? "object"}>`;
        }
    }
    return String(rawCause);
}

function formatCause(rawCause: unknown): string {
    if (rawCause === undefined) return "";
    return `\ncaused by ${describeCause(rawCause)}`;
}

// WebKit (macOS WKWebView) omits the "Name: message" header from Error.stack,
// so a bare stack hides the real cause. Prepend name+message, then the stack.
function formatError(e: Error): string {
    const head = `${e.name}: ${e.message}`;
    const cause = formatCause((e as { cause?: unknown }).cause);
    if (!e.stack) return `${head}${cause}`;
    if (e.stack.startsWith(head)) return `${head}${cause}`;
    return `${head}${cause}\n${e.stack}`;
}

function format(args: unknown[]): string {
    return args
        .map((a) => {
            if (typeof a === "string") return a;
            if (a instanceof Error) return formatError(a);
            try {
                return JSON.stringify(a);
            } catch {
                return String(a);
            }
        })
        .join(" ");
}

function parseStackLine(line: string): string {
    // Find the file:line:col tail at the end of the path.
    const colonCol = line.lastIndexOf(":");
    if (colonCol <= 0) return "";
    const colonLine = line.lastIndexOf(":", colonCol - 1);
    if (colonLine <= 0) return "";
    const col = line.slice(colonCol + 1);
    const lineNo = line.slice(colonLine + 1, colonCol);
    if (!/^\d+$/.test(col) || !/^\d+$/.test(lineNo)) return "";
    const before = line.slice(0, colonLine);
    const sep = Math.max(
        before.lastIndexOf("/"),
        before.lastIndexOf("\\"),
        before.lastIndexOf("("),
        before.lastIndexOf(" "),
    );
    const file = before.slice(sep + 1);
    if (!file.includes(".")) return "";
    return `${file}:${lineNo}`;
}

function callerSource(): string {
    const stack = new Error().stack;
    if (!stack) return "";
    for (const line of stack.split("\n").slice(1)) {
        if (line.includes("/logs.ts")) continue;
        const parsed = parseStackLine(line);
        if (parsed) return parsed;
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
        // Swallow — log forwarding must never throw back into the caller.
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
