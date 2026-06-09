import { UILog } from "@bindings/services";

// Forwards browser console output and uncaught errors into the Go logrus
// pipeline. Originals still fire, so DevTools is unchanged; the Go
// --log-level does the gating.

type Level = "trace" | "debug" | "info" | "warn" | "error";

const METHOD_LEVELS: Record<string, Level> = {
    trace: "trace",
    debug: "debug",
    log: "info",
    info: "info",
    warn: "warn",
    error: "error",
};

// Sources whose output is noise and shouldn't be forwarded.
const IGNORED_SOURCES = new Set(["welcome.ts"]);

let installed = false;

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

// First stack frame outside this module as "<file>:<line>" (best-effort;
// minified prod stacks degrade to chunk names).
function callerSource(): string {
    const stack = new Error().stack;
    if (!stack) return "";
    for (const line of stack.split("\n").slice(1)) {
        if (line.includes("/logs.ts")) continue;
        const m = line.match(/([^/\\() ]+\.[a-z]+):(\d+):\d+/i);
        if (m) return `${m[1]}:${m[2]}`;
    }
    return "";
}

function forward(level: Level, args: unknown[]) {
    try {
        const source = callerSource();
        if (IGNORED_SOURCES.has(source.split(":")[0])) return;
        // Fire-and-forget; don't touch console here (would recurse).
        void UILog.Log(level, source, format(args));
    } catch {
        // swallow
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

    window.addEventListener("error", (e) => {
        forward("error", [`uncaught error: ${e.message}`, e.error ?? ""]);
    });
    window.addEventListener("unhandledrejection", (e) => {
        forward("error", ["unhandled promise rejection:", e.reason]);
    });
}
