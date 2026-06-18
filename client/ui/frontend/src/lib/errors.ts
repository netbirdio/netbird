import { WindowManager } from "@bindings/services";

type ClassifiedError = { short: string; long: string };

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

// Read { short, long } from wherever the classified error sits in the envelope
const toClassifiedError = (v: unknown): ClassifiedError | null => {
    const o = asObject(v);
    if (!o) return null;
    const short = typeof o.short === "string" ? o.short : "";
    const long = typeof o.long === "string" ? o.long : "";
    return short || long ? { short, long } : null;
};

export const formatErrorMessage = (e: unknown): string => {
    const envelope = toWailsEnvelope(e);

    // Prefer the structured { short, long } the daemon classifier produced.
    const classified = toClassifiedError(envelope?.cause) ?? toClassifiedError(envelope);
    if (classified) {
        const { short, long } = classified;
        if (short && long && long !== short) return `${short} Details: ${long}`;
        if (short) return short;
        if (long) return long;
    }

    // Unclassified (a service returned the raw daemon error)
    const message = envelope?.message;
    if (typeof message === "string" && message) return message;
    if (e instanceof Error) return e.message;
    return String(e);
};

export type ErrorDialogOptions = {
    Title: string;
    Message: string;
};

export function errorDialog(options: ErrorDialogOptions): Promise<void> {
    return WindowManager.OpenError(options.Title, options.Message);
}
