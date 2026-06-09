import { WindowManager } from "@bindings/services";

type ClientError = { short?: string; long?: string };

const asClientError = (obj: object): ClientError => {
    const withCause = obj as { cause?: unknown };
    if (withCause.cause && typeof withCause.cause === "object") {
        return withCause.cause;
    }
    return obj;
};

const parseMessageJson = (message: unknown): ClientError | null => {
    if (typeof message !== "string") return null;
    const m = message.trim();
    if (!m.startsWith("{") || !m.endsWith("}")) return null;
    try {
        const parsed: unknown = JSON.parse(m);
        if (parsed && typeof parsed === "object") return asClientError(parsed);
    } catch {
    }
    return null;
};

const extractClientError = (e: unknown): ClientError | null => {
    if (!e || typeof e !== "object") return null;
    const withCause = e as { cause?: unknown; message?: unknown };
    if (withCause.cause && typeof withCause.cause === "object") {
        return withCause.cause;
    }
    return parseMessageJson(withCause.message);
};

export const formatErrorMessage = (e: unknown): string => {
    const ce = extractClientError(e);
    if (ce) {
        const short = typeof ce.short === "string" ? ce.short : "";
        const long = typeof ce.long === "string" ? ce.long : "";
        if (short && long && long !== short) {
            return `${short} Details: ${long}`;
        }
        if (short) return short;
    }
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
