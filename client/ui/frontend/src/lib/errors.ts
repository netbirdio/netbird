import { WindowManager } from "@bindings/services";

type ClassifiedError = { code: string; short: string; long: string; command: string };

const asObject = (v: unknown): Record<string, unknown> | null =>
    v && typeof v === "object" ? (v as Record<string, unknown>) : null;

const parseJsonObject = (s: unknown): Record<string, unknown> | null => {
    if (typeof s !== "string") return null;
    const t = s.trim();
    if (!t.startsWith("{") || !t.endsWith("}")) return null;
    try {
        return asObject(JSON.parse(t));
    } catch {
        return null;
    }
};

const toWailsEnvelope = (e: unknown): Record<string, unknown> | null => {
    const obj = asObject(e);
    if (!obj) return null;
    return asObject(obj.cause) ?? parseJsonObject(obj.message);
};

// Read { code, short, long, command } from wherever the classified error sits in the envelope
const toClassifiedError = (v: unknown): ClassifiedError | null => {
    const o = asObject(v);
    if (!o) return null;
    const code = typeof o.code === "string" ? o.code : "";
    const short = typeof o.short === "string" ? o.short : "";
    const long = typeof o.long === "string" ? o.long : "";
    const command = typeof o.command === "string" ? o.command : "";
    return short || long ? { code, short, long, command } : null;
};

const classify = (e: unknown): ClassifiedError | null => {
    const envelope = toWailsEnvelope(e);
    return toClassifiedError(envelope?.cause) ?? toClassifiedError(envelope);
};

export const formatErrorMessage = (e: unknown): string => {
    // Prefer the structured { short, long } the daemon classifier produced.
    const classified = classify(e);
    if (classified) {
        const { short, long } = classified;
        if (short && long && long !== short) return `${short} Details: ${long}`;
        if (short) return short;
        if (long) return long;
    }

    // Unclassified (a service returned the raw daemon error)
    const envelope = toWailsEnvelope(e);
    const message = envelope?.message;
    if (typeof message === "string" && message) return message;
    if (e instanceof Error) return e.message;
    return String(e);
};

// errorCommand returns a command the user can run to complete an operation the
// daemon refused, when the error carries one (a change that needs elevated
// privileges). Empty for every other error.
export const errorCommand = (e: unknown): string => classify(e)?.command ?? "";

// isDaemonUnavailable reports whether an error means the daemon could not be
// reached or refuses this user. Matches the classified code first and the raw
// gRPC status text second, since not every service classifies its errors.
export const isDaemonUnavailable = (e: unknown): boolean => {
    const code = classify(e)?.code;
    if (code === "daemon_unreachable" || code === "daemon_access_denied") return true;
    const msg = e instanceof Error ? e.message : String(e);
    return msg.includes("code = Unavailable");
};

export type ErrorDialogOptions = {
    Title: string;
    Message: string;
    // Command is shown for copying below the message. Prefer errorDialogFor,
    // which takes it from the error, over setting this by hand.
    Command?: string;
};

export function errorDialog(options: ErrorDialogOptions): Promise<void> {
    return WindowManager.OpenError(options.Title, options.Message, options.Command ?? "");
}

// errorDialogFor opens a dialog for a thrown error, taking both the message and
// any command the daemon attached from the error itself.
//
// Use it wherever the message is just the error. Passing Command by hand is what
// kept the daemon's suggested command off the screen everywhere except Settings,
// since every other caller had to remember to ask for it.
export function errorDialogFor(title: string, e: unknown): Promise<void> {
    return errorDialog({
        Title: title,
        Message: formatErrorMessage(e),
        Command: errorCommand(e),
    });
}
